from typing import Coroutine, Dict, Union, Any, List, Optional
from urllib.parse import unquote
from requests.structures import CaseInsensitiveDict

import http
import socket
import os
import signal
import select
import asyncio
import re
import time
import orjson
import gzip

STATUS_CODES = {c.value: c.phrase for c in http.HTTPStatus}

class Endpoint:
    def __init__(self, path, method, handler):
        self.path: Union[str] = path
        self.methods: List[str] = method
        self.handler: Coroutine = handler
        
    def match(self, path) -> Union[bool, list]: # check endpoint path with request path
        if isinstance(self.path, re.Pattern):
            args = self.path.match(path)
            
            if not args:
                return False
                
            if not (gd := args.groupdict()):
                return True
            
            ret = []
            for k in gd:
                ret.append(args[k])
            
            return ret
        elif isinstance(self.path, str):
            return self.path == path

class Request: # class to handle single request from client
    def __init__(self, client, loop):
        self.client: socket.socket = client
        self.loop: asyncio.AbstractEventLoop = loop
        
        self.type: str = 'GET'
        self.path: str = '/'
        self.url: str = ''
        self.ver: str = 'HTTP/1.1'
        self.body: bytearray = bytearray()
        
        self.extras: dict = {} # ?
        
        self.elapsed: str = ''
        self.code: int = 404

        # UNION IS FUCKING HOT
        self.headers: CaseInsensitiveDict[Union[str, int], Any] = CaseInsensitiveDict()
        self.args: Dict[Union[str, int], Any] = {}
        self.resp_headers: dict[Union[str, int], Any] = {} # easy way to add headers to response :p
        
        self.files: dict[str, Any] = {}
        
        self.headers_list: list = []
        
    async def _handle_headers(self, h: bytes) -> None: # use _ for most internal functions ig xd
        headers = h.decode()
        
        self.type, self.path, self.ver = headers.splitlines()[0].split(' ')
        self.ver = self.ver.split('/')[1]
        
        if '?' in self.path:
            self.path, args = self.path.split('?')
            
            for key, val in [a.split('=', 1) for a in args.split('&')]:
                self.args[key] = val.strip()
                
        for key, val in [hd.split(':', 1) for hd in headers.splitlines()[1:]]:
            self.headers[key] = val.strip()
            
    def parse_form(self) -> None:
        b = self.body.decode()
        
        for arg in b.split('&'):
            key, val = arg.split('=', 1)
            self.args[unquote(key).strip()] = unquote(val).strip() # i am determined to find less ugly way of doing this
            
    def parse_multi(self) -> None:
        bound = '--' + self.headers['Content-Type'].split('boundary=', 1)[1]
        p = self.body.split(bound.encode())[1:]
        
        for part in p[:-1]:
            h, _b = part.split(b'\r\n\r\n', 1)
            b = _b[:-2]

            for key, val in [hd.split(': ', 1) for hd in [d for d in h.decode().split('\r\n')[1:]]]: # what the FUCK :smiley:
                if key == 'Content-Disposition': # we need main content lol     
                    args = {}
                    for key, val in [a.split('=', 1) for a in val.split('; ')[1:]]:
                        args[key] = val[1:-1]
                        
                    if 'filename' in args: # file was sent
                        self.files[args['filename']] = b
                        break
                    elif 'name' in args: # regular arg(?)
                        self.args[args['name']] = b.decode()
                        break
                    
                break # maybe?
            
    async def parse_req(self) -> None:
        b = bytearray()
        while (o := b.find(b'\r\n\r\n')) == -1: # BETTER OFFSET MANAGEMENT
            b += await self.loop.sock_recv(self.client, 1024)
        
        await self._handle_headers(b[:o])
        
        self.body = b[o + 4:] # I AM IN PAIN

        try:
            length = int(self.headers['Content-Length'])
        except KeyError:
            return # header wasn't found, probably faulty request
        
        if to_handle := ((o + 4) + length) - len(b): # there's more to get
            b += b'\x00' * to_handle # empty alloc
            
            v = memoryview(b)[-to_handle:]
            
            while to_handle:
                rb = await self.loop.sock_recv_into(self.client, v)
                v = v[rb:]
                to_handle -= rb

            self.body += memoryview(b)[o + 4 + len(self.body):].tobytes()
            
        if self.type == 'POST' and (_type := self.headers.get('Content-Type')):
                if 'form-data' in _type or _type.startswith('multipart/form-data'):
                    self.parse_multi()
                elif _type in ('application/x-www-form-urlencoded', 'x-www-form'):
                    self.parse_form()
        
    async def send(self, code: int, b: bytes) -> None:
        resp = bytearray()
        rl = [f'HTTP/1.1 {code} {STATUS_CODES.get(code)}']
        
        if b:
            rl.append(f'Content-Length: {len(b)}')
            
        for key, val in self.resp_headers.items():
            rl.append(f'{key}: {val}')
            
        resp += ('\r\n'.join(rl) + '\r\n\r\n').encode()
        
        if b:
            resp += b

        try:
            await self.loop.sock_sendall(self.client, resp)
        except Exception:
            pass
        
class Router:
    def __init__(self, domain: Union[str, set]):
        self.domain: Union[str, set] = domain # i may accept regex in the future
        self.endpoints: set = set() # endpoints current router handles (server can have multiple routers, useful for multi-file impl)

        self.before_reqs: set = set()
        self.after_reqs: set = set()
        
        self.cond: eval = None
        self.validate()
        
    def validate(self) -> None: # WHY.
        if isinstance(self.domain, set):
            self.cond = lambda d: d in self.domain
        elif isinstance(self.domain, str):
            self.cond = lambda d: d == self.domain
        
    def route(self, path: str, method: List[str] = ['GET']): # route decorator
        def wrapper(_coro: Coroutine):
            if all(c in path for c in ('<', '>')): # thank you lenforiee cus i absolutely hate regex
                np = re.compile(rf"{path.replace('<', '(?P<').replace('>', '>.+)')}")
                self.endpoints.add(Endpoint(np, method, _coro))
                return _coro

            self.endpoints.add(Endpoint(path, method, _coro))
            return _coro
        return wrapper
    
    def before_request(self):
        def wrapper(_coro: Coroutine):
            self.before_reqs.add(_coro)
            return _coro
        return wrapper
    
    def after_request(self):
        def wrapper(_coro: Coroutine):
            self.after_reqs.add(_coro)
            return _coro
        return wrapper
        
class Xevel: # osu shall never leave my roots
    def __init__(self, address, **extras):
        self.address: Union[tuple, str] = address
        self.socket: Optional[socket.socket] = None # this is bound to change i think
        self.loop: asyncio.AbstractEventLoop = extras.get('loop', asyncio.get_event_loop()) # allow people to pass their own loop for whatever reason ig
        
        self.gzip: int = extras.get('gzip', 0)

        self.routers: set = set()
        self.before_serves: set = set()
        self.after_serves: set = set()
        self.coros: set = set() # task coros (before being created)
        self.tasks: set = set() # tasks (after being created)

    def add_router(self, router: Router) -> None:
        self.routers.add(router)
        
    def add_task(self, _coro) -> None:
        self.coros.add(_coro)

    def before_serving(self):
        def wrapper(_coro: Coroutine):
            self.before_serves.add(_coro)
            return _coro
        return wrapper

    def after_serving(self):
        def wrapper(_coro: Coroutine):
            self.after_serves.add(_coro)
            return _coro
        return wrapper
    
    async def handle_req(self, c: socket.socket) -> None:
        req = Request(c, self.loop) # request object kinda cooooooool i think
        await req.parse_req()
        
        if 'Host' not in req.headers: # PIECE OF SHIT
            c.shutdown(socket.SHUT_RDWR)
            c.close()
            return
        
        await self.handle_route(req)
        
        try: # shutdown client once request is complete
            c.shutdown(socket.SHUT_RDWR)
            c.close()
        except socket.error:
            pass # dont see why socket would decide to error but alas
        
    async def handle_route(self, req) -> None:
        start = time.time()

        host = req.headers['Host'] # find router that handles correct host
        path = req.path
        code = 404 # force 404 code until we can actually complete request/set different code
        resp = b'Route not found!' # same as above
        
        router = self.get_router(host)
        if not router:
            return await req.send(code, resp) # couldn't find any router to handle request, return 404
        
        for _coro in router.before_reqs:
            await _coro(req) # handle any coroutines before making the request
            
        # ensure we have an endpoint in this router
        for ep in router.endpoints:
            if c := ep.match(path): # check matching endpoints
                if isinstance(c, list):
                    resp = await ep.handler(req, *c)
                else:
                    resp = await ep.handler(req)

                code = 200
                
                if req.type not in ep.methods:
                    resp = b'Disallowed method!'
                    code = 405
        
        if isinstance(resp, tuple):
            code, resp = resp # fix response into var
            
        if isinstance(resp, (dict, list)): # list usually contains dicts
            try:
                req.resp_headers['Content-Type'] = 'application/json' # fix content type for browsers
                resp = orjson.dumps(resp) # jsonify response
            except Exception:
                pass # probably list isnt json or smth
            
        if isinstance(resp, str):
            resp = resp.encode() # encode response into bytes for client ready xd
            
        req.url = host + path
        req.code = code
        
        if (
                self.gzip and 'Accept-Encoding' in req.headers and 'gzip' in req.headers['Accept-Encoding'] 
                and len(resp) > 1500
        ):
            if not (
                    'Content-Type' in req.resp_headers and 
                    req.resp_headers['Content-Type'] in (
                        'image/jpeg', 'image/png'
                    )
            ):
                resp = gzip.compress(resp, self.gzip)
                req.resp_headers['Content-Encoding'] = 'gzip'
            
        await req.send(code, resp) # finally send request to client xd
        
        end = time.time()
        taken = (end - start)
        
        if taken < 1:
            req.elapsed = f'{round(taken * 1000, 2)}ms'
        else:
            req.elapsed = f'{round(taken, 2)}s'
        
        for _coro in router.after_reqs:
            await _coro(req) # handle any coroutines before ending request | send request so they can take some attributes from it
            
    def get_router(self, host: str) -> Optional[Router]:
        for r in self.routers:
            if r.cond(host):
                return r

    def start(self) -> None:
        async def run_server() -> None:
            if isinstance(self.address, str):
                self.socket = socket.socket(socket.AF_UNIX)
                t = socket.AF_UNIX
            elif isinstance(self.address, tuple):
                self.socket = socket.socket(socket.AF_INET)
                t = socket.AF_INET
            else:
                raise TypeError('Please use the correct address format!') # raising exceptions kinda cooooooool
            
            if os.name == 'nt':
                raise RuntimeError('Xevel doesn\'t support Windows!')
            
            if t is socket.AF_UNIX and os.path.exists(self.address):
                os.remove(self.address)
                    
            for _coro in self.before_serves:
                await _coro()
                
            for _coro in self.coros:
                if isinstance(_coro, tuple):
                    coro, args = _coro
                    _t = self.loop.create_task(coro(args))
                else:
                    _t = self.loop.create_task(_coro())
                
                self.tasks.add(_t)
            
            self.socket.setblocking(False)
            
            if t is socket.AF_INET:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            self.socket.bind(self.address)

            if t is socket.AF_UNIX:
                os.chmod(self.address, 0o777) # full permissions to socket file to prevent any potential perm issues xd
                
            self.socket.listen()
            
            # i am trying to make this as original as possible while it also being my first attempt, bare with me!!
            r, w = os.pipe()
            os.set_blocking(w, False)
            signal.set_wakeup_fd(w)
            
            close = False
            
            while True: # loop to accept connections? i might redo this system when i learn more about the internals of what im doing here...
                await asyncio.sleep(0.001)
                rl, _, _ = select.select([self.socket, r], [], [], 0) # what :smiley: | ok i kinda understand this now :p
                
                for rd in rl:
                    if rd is self.socket: # new connection
                        req, _ = await self.loop.sock_accept(self.socket)
                        t = self.loop.create_task(self.handle_req(req))
                    elif rd is r: # shutdown signal!!!
                        rcv = signal.Signals(os.read(r, 1)[0])
                        if rcv is signal.SIGINT:
                            print('\x1b[2K', end='\r') # cleaner shut down
                        close = True
                    else: # ?
                        raise RuntimeError('Error when processing reader...')
                    
                if close:
                    break
    
            # if we have reached this point, shutdown signal has been requested
            for sock_file in (self.socket.fileno(), r, w):
                os.close(sock_file)
                
            signal.set_wakeup_fd(-1)
            
            for _coro in self.after_serves:
                await _coro()
                
            if self.tasks:
                for t in self.tasks:
                    t.cancel()
                    
                await asyncio.gather(*self.tasks, return_exceptions=False)
                
                if running := [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]:
                    try:
                        await asyncio.wait(running, loop=self.loop, timeout=5.0)
                    except asyncio.TimeoutError:
                        ta = []
                        for t in running:
                            if not t.cancelled():
                                t.cancel()
                                ta.append(t)
                        await asyncio.gather(*ta, return_exceptions=False)
        
        def _ignore_signal(s, fr): # when can we natively use pass without a func PLEASE
            pass
        
        def _run_cb(f): # shit static to stop loop when done
            self.loop.stop()
        
        # we wanna ignore these signals?
        if os.name == 'nt': # windows
            sig_ig = (signal.SIGINT, signal.SIGTERM)
        else:
            sig_ig = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)

        for sig in sig_ig:
            signal.signal(sig, _ignore_signal)
        
        f = asyncio.ensure_future(run_server(), loop=self.loop)
        f.add_done_callback(_run_cb)
            
        try:
            self.loop.run_forever()
        finally:
            f.remove_done_callback(_run_cb)
            self.loop.close()
