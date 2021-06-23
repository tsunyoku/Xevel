from typing import Coroutine, Dict, Union, Any, List
from .codes import STATUS_CODES

import socket
import os
import signal
import select
import asyncio
import re

class Endpoint:
    def __init__(self, path, method, handler):
        self.path: Union[str, re.Pattern] = path
        self.methods: List[str] = method
        self.handler: Coroutine = handler
        
    def match(self, path): # check endpoint path with request path
        return self.path == path

class Request: # class to handle single request from client
    def __init__(self, client, loop):
        self.client = client
        self.loop = loop
        
        self.type = 'GET'
        self.path = '/'
        self.url = ''
        self.ver = 'HTTP/1.1'
        self.body = b''

        # UNION IS FUCKING HOT
        self.headers: Dict[Union[str, int], Any] = {}
        self.args: Dict[Union[str, int], Any] = {}
        self.resp_headers: dict[Union[str, int], Any] = {} # easy way to add headers to response :p
        
        self.headers_list: list = []
        
    async def _handle_headers(self, h): # use _ for most internal functions ig xd
        headers = h.decode()
        
        if not headers:
            return # ?
        
        self.type, self.path, self.ver = headers.splitlines()[0].split(' ') # good old client requests!
        
        if '?' in self.path: # we can assume there's args in path
            self.path, a = self.path.split('?') # update true path & get args in raw form
            
            for arg in a.split('&'):
                key, val = arg.split('=', 1)
                self.args[key] = val.strip() # strip?
                
        for header in headers.splitlines()[1:]: # handle rest of provided headers
            key, val = header.split(':', 1)
            self.headers[key] = val.lstrip() # strip?
            
    async def parse_req(self):
        b = bytearray()
        while b'\r\n\r\n' not in b:
            b += await self.loop.sock_recv(self.client, 1024)
        
        spl = b.split(b'\r\n\r\n')
        await self._handle_headers(spl[0])
        
        self.body = b[len(spl[0]) + 4:] # I AM IN PAIN

        try:
            length = int(self.headers['Content-Length'])
        except KeyError:
            return # header wasn't found, probably faulty request
        
        if len(self.body) != length: # there's more to get
            to_handle = length - len(self.body)
            bb = bytearray(to_handle) # init bytearray with empty bytes remaining
            v = memoryview(bb) # offset or something?
            
            while to_handle: # loop til complete
                rb = await self.loop.sock_recv_into(self.client, v)
                v = v[rb:]
                to_handle -= rb
                
            self.body += bytes(bb)
            
        # TODO: handle multipart args/request
        
    async def send(self, code, b):
        self.headers_list.insert(0, f'HTTP/1.1 {code} {STATUS_CODES.get(code)}')
        
        if b:
            self.headers_list.insert(1, f'Content-Length: {len(b)}')
        
        for k, v in self.resp_headers.items():
            self.headers_list.append(f'{k}: {v}')
            
        headers = '\r\n'.join(self.headers_list)
        resp = f'{headers}\r\n\r\n'.encode()
        
        if b:
            resp += b
            
        await self.loop.sock_sendall(self.client, resp)
        
class Router:
    def __init__(self, domain):
        self.domain: Union[str, set] = domain # i may accept regex in the future
        self.endpoints = set() # endpoints current router handles (server can have multiple routers, useful for multi-file impl)

        self.before_reqs = set()
        self.after_reqs = set()
        
        self.cond: eval = None
        self.validate()
        
    def validate(self): # WHY.
        if isinstance(self.domain, set):
            self.cond = lambda d: d in self.domain
        elif isinstance(self.domain, str):
            self.cond = lambda d: d == self.domain
        
    def route(self, path, method: List[str] = ['GET']): # route decorator
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
        self.address = address
        self.socket = None # this is bound to change i think
        self.loop = extras.get('loop', asyncio.get_event_loop()) # allow people to pass their own loop for whatever reason ig

        self.routers = set()
        self.before_serves = set()
        self.after_serves = set()

    def add_router(self, router: Router):
        self.routers.add(router)

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
    
    async def handle_req(self, c):
        req = Request(c, self.loop) # request object kinda cooooooool i think
        await req.parse_req()
        
        await self.handle_route(req)
        
        try: # shutdown client once request is complete
            c.shutdown(socket.SHUT_RDWR)
            c.close()
        except socket.error:
            pass # dont see why socket would decide to error but alas
        
    async def handle_route(self, req):
        host = req.headers['Host'] # find router that handles correct host
        path = req.path
        code = 404 # force 404 code until we can actually complete request/set different code
        resp = b'Route not found!' # same as above
        
        router = self.get_router(host)
        if not router:
            return await req.send(code, resp) # couldn't find any router to handle request, return 404
        
        for _coro in router.before_reqs:
            await _coro() # handle any coroutines before making the request
            
        # ensure we have an endpoint in this router
        for ep in router.endpoints:
            if c := ep.match(path): # check matching endpoints
                resp = await ep.handler(req)
                code = 200
                
                if req.type not in ep.methods:
                    resp = b'Disallowed method!'
                    code = 405
        
        if isinstance(resp, tuple):
            code, resp = resp # fix response into var
            
        if isinstance(resp, str):
            resp = resp.encode() # encode response into bytes for client ready xd
            
        req.url = host + path
            
        await req.send(code, resp) # finally send request to client xd
        
        for _coro in router.after_reqs:
            await _coro(req) # handle any coroutines before ending request | send request so they can take some attributes from it
            
    def get_router(self, host):
        for r in self.routers:
            if r.cond(host):
                return r

    def start(self):
        async def run_server():
            if isinstance(self.address, str):
                self.socket = socket.socket(socket.AF_UNIX)
                t = socket.AF_UNIX
            elif isinstance(self.address, tuple):
                self.socket = socket.socket(socket.AF_INET)
                t = socket.AF_INET
            else:
                raise TypeError('Please use the correct address format!') # raising exceptions kinda cooooooool
            
            if t is socket.AF_UNIX: # dddddddddddddd
                if os.path.exists(self.address):
                    os.remove(self.address)
                    
            for _coro in self.before_serves:
                await _coro()
            
            self.socket.setblocking(False)
            self.socket.bind(self.address)
            
            if t is socket.AF_UNIX:
                os.chmod(self.address, 0o777) # full permissions to socket file to prevent any potential perm issues xd
                
            self.socket.listen(5)
            
            # i am trying to make this as original as possible while it also being my first attempt, bare with me!!
            r, w = os.pipe()
            os.set_blocking(w, False)
            signal.set_wakeup_fd(w)
            
            close = False
            
            while True: # loop to accept connections? i might redo this system when i learn more about the internals of what im doing here...
                await asyncio.sleep(0.01)
                rl, _, _ = select.select([self.socket, r], [], [], 0) # what :smiley:
                
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
        
        def _ignore_signal(s, fr): # when can we natively use pass without a func PLEASE
            pass
        
        def _run_cb(f): # shit static to stop loop when done
            self.loop.stop()
        
        # we wanna ignore these signals?
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, _ignore_signal)
        
        f = asyncio.ensure_future(run_server(), loop=self.loop)
        f.add_done_callback(_run_cb)
            
        try:
            self.loop.run_forever()
        finally:
            self.loop.close()