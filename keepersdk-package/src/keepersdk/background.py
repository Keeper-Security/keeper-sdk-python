import asyncio
import atexit
import threading
import time
from typing import Optional


_thread: Optional[threading.Thread] = None
_loop: Optional[asyncio.AbstractEventLoop] = None


def _setup_asyncio_loop():
    global _loop
    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
    _loop.run_forever()


def init() -> None:
    global _thread, _loop
    if _thread is None:
        _thread = threading.Thread(target=_setup_asyncio_loop, daemon=True)
        _thread.start()
        time.sleep(0.1)


async def _stop_loop():
    if _loop and _loop.is_running():
        _loop.stop()


def get_loop() -> asyncio.AbstractEventLoop:
    global _loop
    assert _loop
    return _loop


def stop() -> None:
    global _thread, _loop
    if isinstance(_thread, threading.Thread) and _thread.is_alive():
        assert _loop is not None
        asyncio.run_coroutine_threadsafe(_stop_loop(), _loop)
        _thread.join(2)
        _loop.close()
        _loop = None
        _thread = None


atexit.register(stop)