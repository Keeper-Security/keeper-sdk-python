import asyncio
import json
import ssl
from typing import Optional, Dict, Any

import websockets
import websockets.frames
import websockets.protocol
import websockets.exceptions

from . import endpoint, notifications, keeper_auth
from .. import crypto, utils, background
from ..proto import push_pb2


class KeeperPushNotifications(notifications.FanOut[Dict[str, Any]]):
    """Keeper Security push notification handler with WebSocket connection management."""

    def __init__(self) -> None:
        super().__init__()
        self._ws_app: Optional[websockets.ClientConnection] = None
        self._use_pushes = False

    async def main_loop(self, push_url: str, transmission_key: bytes, data: Optional[bytes] = None):
        """Main WebSocket connection loop for receiving push notifications."""
        logger = utils.get_logger()
        try:
            await self.close_ws()
        except Exception as e:
            logger.debug('Push notification close error: %s', e)

        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if not endpoint.get_certificate_check():
            ssl_context.verify_mode = ssl.CERT_NONE

        ws_app = None
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
        """Close the WebSocket connection if open."""
        self._use_pushes = False
        ws_app = self._ws_app
        if ws_app and ws_app.state == websockets.protocol.State.OPEN:
            try:
                await ws_app.close(websockets.frames.CloseCode.GOING_AWAY)
            except Exception:
                pass

    def connect_to_push_channel(self, push_url: str, transmission_key: bytes, data: Optional[bytes] = None) -> None:
        """Connect to a push notification channel."""
        asyncio.run_coroutine_threadsafe(self.main_loop(push_url, transmission_key, data), background.get_loop())

    def shutdown(self):
        """Shutdown push notifications and close connections."""
        super().shutdown()
        asyncio.run_coroutine_threadsafe(self.close_ws(), loop=background.get_loop()).result()

    async def _push_server_guard(self, auth: keeper_auth.KeeperAuth):
        """Guard loop that maintains push notification connection with keep-alive."""
        transmission_key = utils.generate_aes_key()
        self._use_pushes = True
        try:
            while self._use_pushes:
                url = auth.keeper_endpoint.get_push_url(
                    transmission_key, auth.auth_context.device_token, auth.auth_context.message_session_uid)
                await self.main_loop(url, transmission_key, auth.auth_context.session_token)
                auth.execute_auth_rest('keep_alive', None)
        except Exception as e:
            utils.get_logger().debug(e)
        finally:
            self._use_pushes = False

    def start_push_server(self, auth: keeper_auth.KeeperAuth):
        """Start push notification server with authenticated session."""
        asyncio.run_coroutine_threadsafe(self._push_server_guard(auth), loop=background.get_loop())
