import abc
import asyncio
import ssl
from dataclasses import dataclass
from typing import Optional, TypeVar, Generic, Callable, List, Union, Dict, Any

import websockets
import websockets.exceptions
import websockets.frames
import websockets.protocol

from . import endpoint
from .. import utils, background

M = TypeVar('M')

PUSH_SHUTDOWN_TIMEOUT = 5


class FanOut(Generic[M]):
    """Generic fan-out/publish-subscribe pattern for distributing messages to multiple callbacks."""

    def __init__(self) -> None:
        self._callbacks: List[Callable[[M], Optional[bool]]] = []
        self._is_completed = False

    @property
    def is_completed(self):
        return self._is_completed

    def push(self, message: M) -> None:
        """Push a message to all registered callbacks.

        Callbacks that return True or raise exceptions are automatically removed.
        """
        if self._is_completed:
            return
        to_remove = []
        for i, cb in enumerate(self._callbacks):
            try:
                rs = cb(message)
                if isinstance(rs, bool) and rs is True:
                    to_remove.append(i)
            except Exception:
                to_remove.append(i)
        self._remove_indexes(to_remove)

    def register_callback(self, callback: Callable[[M], Optional[bool]]) -> None:
        """Register a callback to receive pushed messages."""
        if self._is_completed:
            return
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[M], Optional[bool]]) -> None:
        """Remove a specific callback."""
        if self._is_completed:
            return
        to_remove = []
        for i, cb in enumerate(self._callbacks):
            if cb == callback:
                to_remove.append(i)
        self._remove_indexes(to_remove)

    def remove_all(self):
        """Remove all registered callbacks."""
        self._callbacks.clear()

    def _remove_indexes(self, to_remove: List[int]):
        while to_remove:
            idx = to_remove.pop()
            if 0 <= idx < len(self._callbacks):
                del self._callbacks[idx]

    def shutdown(self):
        """Shutdown the FanOut, marking it as completed and removing all callbacks."""
        self._is_completed = True
        self._callbacks.clear()


@dataclass(frozen=True)
class PushConnectionParameters:
    url: str
    headers: Optional[Dict[str, str]] = None


class BasePushNotifications(abc.ABC, FanOut[Dict[str, Any]]):
    def __init__(self) -> None:
        super().__init__()
        self._ws_app: Optional[websockets.ClientConnection] = None
        self._running_task: Optional[asyncio.Future] = None
        self.use_pushes = False

    @abc.abstractmethod
    def on_messaged_received(self, message: Union[str, bytes]):
        pass

    @abc.abstractmethod
    async def on_connected(self):
        pass

    @abc.abstractmethod
    def get_connection_parameters(self) -> Optional[PushConnectionParameters]:
        pass

    async def main_loop(self) -> None:
        logger = utils.get_logger()

        ssl_context: Optional[ssl.SSLContext] = None
        while self.use_pushes:
            push_parameters: Optional[PushConnectionParameters] = self.get_connection_parameters()
            if push_parameters is None:
                break
            if not push_parameters.url:
                break

            url = push_parameters.url
            headers = push_parameters.headers or {}

            if url.startswith('wss://'):
                ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                if not endpoint.get_certificate_check():
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
            try:
                async with websockets.connect(
                        url, additional_headers=headers, ping_interval=30, open_timeout=4, ssl=ssl_context) as ws_app:
                    self._ws_app = ws_app
                    await self.on_connected()

                    async for message in ws_app:
                        try:
                            self.on_messaged_received(message)
                        except Exception as e:
                            logger.debug('Push notification: decrypt error: ', e)
            except Exception as e:
                logger.debug('Push notification: exception: %s', e)
                self.use_pushes = False

        logger.debug('Push notification: exit.')
        if self._ws_app == ws_app:
            self._ws_app = None

    async def send_message(self, message: Union[str, bytes]):
        if self._ws_app and self._ws_app.state == websockets.protocol.State.OPEN:
            await self._ws_app.send(message)

    async def close_ws(self):
        logger = utils.get_logger()
        try:
            ws_app = self._ws_app
            # The server may have started closing already (e.g. on logout); wait for that to finish too.
            if ws_app and ws_app.state != websockets.protocol.State.CLOSED:
                await ws_app.close(websockets.frames.CloseCode.GOING_AWAY)
        except Exception as e:
            logger.debug('Push notification: close error: %s', e)

        running_task = self._running_task
        if running_task is None:
            return
        if not running_task.done():
            _, pending = await asyncio.wait([running_task], timeout=PUSH_SHUTDOWN_TIMEOUT)
            if pending:
                running_task.cancel()
                await asyncio.wait([running_task], timeout=PUSH_SHUTDOWN_TIMEOUT)
        if running_task.done():
            if not running_task.cancelled() and running_task.exception():
                logger.debug('Push notification: task error: %s', running_task.exception())
            self._running_task = None
        else:
            # Keep the reference so connect_to_push_channel refuses to start a second task.
            logger.warning('Push notification: task did not stop within %d seconds', PUSH_SHUTDOWN_TIMEOUT)

    async def _start_main_loop(self) -> asyncio.Task:
        return asyncio.create_task(self.main_loop())

    def connect_to_push_channel(self) -> None:
        running_task = self._running_task
        if running_task and not running_task.done():
            raise Exception("Already running")

        self.use_pushes = True
        # Create the task on the background loop and keep the task itself (not a concurrent wrapper)
        # so close_ws can tell when main_loop has really finished.
        self._running_task = asyncio.run_coroutine_threadsafe(
            self._start_main_loop(), background.get_loop()).result()

    def shutdown(self):
        self.use_pushes = False
        asyncio.run_coroutine_threadsafe(self.close_ws(), loop=background.get_loop()).result()
        super().shutdown()
