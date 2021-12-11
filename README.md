# Xevel
My first attempt at a python ASGI server

Xevel is very much my first attempt at an ASGI server and it is definitely not perfect. I am open to any PRs or issues if you come across any problems.

NOTE: This will only work on UNIX-based systems.

A basic use example of Xevel could look like this:

```python
from xevel import *

web = Xevel(
    ("localhost", 9208)
)  # you can use tuples for port setups ('localhost', PORT') or unix sockets (provide file location as string)
# ('localhost', 9208) # inet
# '/tmp/test.sock' # unix

router = Router(
    "localhost:9208"
)  # force routers to only accept connections from certain domain/subdomains. can provide 1 as a string or multiple as a list


@router.before_request()
async def breq(req):
    print("before request is running!!!")


@router.after_request()
async def areq(req):
    print(f"after request is running!!! endpoint: {req.url}")


@router.route("/test")
async def test_route(req):
    req.resp_headers["XD"] = "lol"
    return "asgi server works no way!!!"


@web.before_serving()
async def before():
    print("before serving is running!!!")


@web.after_serving()
async def after():
    print("after serving is running!!!")


web.add_router(router)
web.start()
```
