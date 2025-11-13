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


def get_loop() -> asyncio.AbstractEventLoop:
    global _loop
    assert _loop
    return _loop


def stop() -> None:
    global _thread, _loop
    if isinstance(_thread, threading.Thread) and _thread.is_alive():
        assert _loop is not None

        # Cancel all pending tasks before stopping the loop
        def cancel_all_tasks():
            tasks = [task for task in asyncio.all_tasks(_loop) if not task.done()]
            for task in tasks:
                task.cancel()

        _loop.call_soon_threadsafe(cancel_all_tasks)

        # Give tasks time to handle cancellation
        time.sleep(0.3)

        # Stop the loop
        _loop.call_soon_threadsafe(_loop.stop)

        # Wait for thread to finish
        _thread.join(4)

        # Close the loop
        if _loop and not _loop.is_closed():
            _loop.close()

        _loop = None
        _thread = None


atexit.register(stop)