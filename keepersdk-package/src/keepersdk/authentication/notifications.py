import abc
import asyncio
import json
import ssl
from typing import Optional, TypeVar, Generic, Callable, List, Dict, Any, Union

import websockets
import websockets.frames
import websockets.protocol
import websockets.exceptions

from .. import crypto, utils, background
from ..proto import push_pb2
from . import endpoint

M = TypeVar('M')


class FanOut(Generic[M]):
    def __init__(self) -> None:
        self._callbacks: List[Callable[[M], Optional[bool]]] = []
        self._is_completed = False

    @property
    def is_completed(self):
        return self._is_completed

    def push(self, message: M) -> None:
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
        if self._is_completed:
            return
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[M], Optional[bool]]) -> None:
        if self._is_completed:
            return
        to_remove = []
        for i, cb in enumerate(self._callbacks):
            if cb == callback:
                to_remove.append(i)
        self._remove_indexes(to_remove)

    def remove_all(self):
        self._callbacks.clear()

    def _remove_indexes(self, to_remove: List[int]):
        while to_remove:
            idx = to_remove.pop()
            if 0 <= idx < len(self._callbacks):
                del self._callbacks[idx]

    def shutdown(self):
        self._is_completed = True
        self._callbacks.clear()


class BasePushNotifications(abc.ABC):
    def __init__(self) -> None:
        super().__init__()
        self._ws_app: Optional[websockets.ClientConnection] = None

    @abc.abstractmethod
    def on_messaged_received(self, message: Union[str, bytes]):
        pass

    @abc.abstractmethod
    async def on_connected(self):
        pass

    async def main_loop(self, *, url: str, headers: Optional[Dict[str, str]]=None):
        logger = utils.get_logger()
        try:
            await self.close_ws()
        except Exception as e:
            logger.debug('Push notification close error: %s', e)

        ssl_context: Optional[ssl.SSLContext] = None
        if url.startswith('wss://'):
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if not endpoint.get_certificate_check():
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

        logger.debug('Push notification: exit.')
        if self._ws_app == ws_app:
            self._ws_app = None

    async def send_message(self, message: Union[str, bytes]):
        if self._ws_app and self._ws_app.state == websockets.protocol.State.OPEN:
            await self._ws_app.send(message)

    async def close_ws(self):
        ws_app = self._ws_app
        if ws_app and ws_app.state == websockets.protocol.State.OPEN:
            try:
                await ws_app.close(websockets.frames.CloseCode.GOING_AWAY)
            except Exception:
                pass

    def close(self):
        asyncio.run_coroutine_threadsafe(self.close_ws(), loop=background.get_loop()).result()


class KeeperPushNotifications(BasePushNotifications, FanOut[Dict[str, Any]]):
    def __init__(self) -> None:
        super().__init__()
        self.transmission_key: Optional[bytes] = None
        self.session_token: Optional[bytes] = None

    def on_messaged_received(self, message: Union[str, bytes]):
        if isinstance(message, bytes):
            if self.transmission_key:
                decrypted_data = crypto.decrypt_aes_v2(message, self.transmission_key)
            else:
                decrypted_data = message
            rs = push_pb2.WssClientResponse()
            rs.ParseFromString(decrypted_data)
            self.push(json.loads(rs.message))

    async def on_connected(self):
        if self.session_token:
            await self.send_message(utils.base64_url_encode(self.session_token))

    def connect_to_push_channel(self, push_url: str, transmission_key: bytes, data: Optional[bytes]=None) -> None:
        self.transmission_key = transmission_key
        self.session_token = data
        asyncio.run_coroutine_threadsafe(self.main_loop(url=push_url, headers=None), background.get_loop())

    def shutdown(self):
        BasePushNotifications.close(self)
        FanOut.shutdown(self)
