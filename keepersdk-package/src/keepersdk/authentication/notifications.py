import asyncio
import json
import ssl
from typing import Optional, TypeVar, Generic, Callable, List, Dict, Any

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


class KeeperPushNotifications(FanOut[Dict[str, Any]]):
    def __init__(self) -> None:
        super().__init__()
        self._ws_app: Optional[websockets.ClientProtocol] = None

    async def main_loop(self, push_url: str, transmission_key: bytes, data: Optional[bytes] = None):
        logger = utils.get_logger()
        try:
            await self.close_ws()
        except Exception as e:
            logger.debug('Push notification close error: %s', e)

        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if not endpoint.get_certificate_check():
            ssl_context.verify_mode = ssl.CERT_NONE

        try:
            async with websockets.connect(push_url, ping_interval=30, open_timeout=4, ssl=ssl_context) as ws_app:
                self._ws_app = ws_app
                if data:
                    await ws_app.send(utils.base64_url_encode(data))
                async for message in ws_app:
                    if isinstance(message, bytes):
                        try:
                            decrypted_data = crypto.decrypt_aes_v2(message, transmission_key)
                            rs = push_pb2.WssClientResponse()
                            rs.ParseFromString(decrypted_data)
                            self.push(json.loads(rs.message))
                        except Exception as e:
                            logger.debug('Push notification: decrypt error: ', e)
        except Exception as e:
            logger.debug('Push notification: exception: %s', e)

        logger.debug('Push notification: exit.')
        if self._ws_app == ws_app:
            self._ws_app = None

    async def close_ws(self):
        ws_app = self._ws_app
        if ws_app and ws_app.state == websockets.protocol.State.OPEN:
            try:
                await ws_app.close(websockets.frames.CloseCode.GOING_AWAY)
            except Exception:
                pass

    def connect_to_push_channel(self, push_url: str, transmission_key: bytes, data: Optional[bytes]=None) -> None:
        asyncio.run_coroutine_threadsafe(self.main_loop(push_url, transmission_key, data), background.get_loop())

    def shutdown(self):
        super().shutdown()
        asyncio.run_coroutine_threadsafe(self.close_ws(), loop=background.get_loop()).result()
