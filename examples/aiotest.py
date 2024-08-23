import asyncio
import sys
import threading
import time
from typing import Tuple

import httpx
import websockets

_loop = asyncio.new_event_loop()

def _setup_asyncio_loop():
    asyncio.set_event_loop(_loop)
    try:
        _loop.run_forever()
    finally:
        print('Closing loop')

t = threading.Thread(target=_setup_asyncio_loop, daemon=True)
t.start()
time.sleep(0.1)

async def fetch(url: str) -> Tuple[str, int]:
    """Does HTTP get on url and returns url and status code"""
    async with httpx.AsyncClient() as session:
        response = await session.get(url, follow_redirects=False)
        return url, response.status_code

async def wait_for():
    return await fetch('http://google.com')

async def stop_loop():
    if _loop.is_running():
        _loop.stop()



async def test_websockets():
    ws = await websockets.connect('wss://socketsbay.com/wss/v2/1/demo/')
    print('connected')
    m = b'aaaaa'
    await ws.send(m)
    print(f'sent: {m}')
    async for message in ws:
        print(f'received: {message}')


if __name__ == '__main__':
    f = asyncio.run_coroutine_threadsafe(test_websockets(), _loop)
    f.result()
    asyncio.run_coroutine_threadsafe(stop_loop(), _loop)
    t.join()
    _loop.close()
    time.sleep(1)
    print('Done')
