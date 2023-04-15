#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import json
import threading
from typing import Optional, TypeVar, Generic, Callable, List, Dict, Any

import websocket

from .. import crypto, utils
from ..proto import push_pb2


M = TypeVar('M')


class FanOut(Generic[M]):
    def __init__(self):
        self._callbacks = []         # type: List[Callable[[M], Optional[bool]]]
        self._is_completed = False   # type: bool

    @property
    def is_completed(self):   # type: () -> bool
        return self._is_completed

    def push(self, message):   # type: (M) -> None
        if self._is_completed:
            return
        to_remove = []
        for i, cb in enumerate(self._callbacks):
            try:
                rs = cb(message)
                if isinstance(rs, bool) and rs is True:
                    to_remove.append(i)
            except:
                to_remove.append(i)
        self._remove_indexes(to_remove)

    def register_callback(self, callback):  # type: (Callable[[M], Optional[bool]]) -> None
        if self._is_completed:
            return
        self._callbacks.append(callback)

    def remove_callback(self, callback):   # type: (Callable[[M], Optional[bool]]) -> None
        if self._is_completed:
            return
        to_remove = []
        for i, cb in enumerate(self._callbacks):
            if cb == callback:
                to_remove.append(i)
        self._remove_indexes(to_remove)

    def remove_all(self):   # type: () -> None
        self._callbacks.clear()

    def _remove_indexes(self, to_remove):
        while to_remove:
            idx = to_remove.pop()
            if 0 <= idx < len(self._callbacks):
                del self._callbacks[idx]

    def shutdown(self):   # type: () -> None
        self._is_completed = True
        self._callbacks.clear()


class KeeperPushNotifications(FanOut[Dict[str, Any]]):
    def __init__(self, transmission_key):   # type: (bytes) -> None
        FanOut.__init__(self)
        self._transmission_key = transmission_key
        self.ws_app = None   # type: Optional[websocket.WebSocketApp]
        self._thread = None  # type: Optional[threading.Thread]
        self.buffer = b''    # type: bytes
        self.logger = utils.get_logger()

    def on_open(self, ws_app):
        self.ws_app = ws_app

    def on_data(self, _, data, data_type, continue_flag):
        if data_type == websocket.ABNF.OPCODE_BINARY:
            self.buffer += data
        if continue_flag:
            try:
                decrypted_data = crypto.decrypt_aes_v2(self.buffer, self._transmission_key)
                rs = push_pb2.WssClientResponse()
                rs.ParseFromString(decrypted_data)
                self.push(json.loads(rs.message))
            except Exception as e:
                self.logger.debug('Push notification: decrypt error: ', e)
            self.buffer = b''

    def on_error(self, ws_app, error):
        self.logger.debug('WebSocket error: %s', str(error))
        self.shutdown()
        if self.ws_app == ws_app:
            self.ws_app = None

    def on_close(self, ws_app, close_code, close_message):
        self.logger.debug('WebSocket is closed with code %d: %s', close_code, close_message)
        if ws_app == self.ws_app:
            self.shutdown()
            self.ws_app = None

    def connect_to_push_channel(self, endpoint_uri):   # type: (str) -> None
        ws_app = websocket.WebSocketApp(
            endpoint_uri, on_open=self.on_open, on_data=self.on_data, on_error=self.on_error, on_close=self.on_close)
        self._thread = threading.Thread(target=lambda: ws_app.run_forever(), daemon=True)
        self._thread.start()

    def send_to_push_channel(self, data, encrypted):   # type: (bytes, bool) -> None
        if self.ws_app:
            if encrypted:
                data = crypto.encrypt_aes_v2(data, self._transmission_key)
            self.ws_app.send(data, websocket.ABNF.OPCODE_BINARY)

    def shutdown(self):
        if self.ws_app:
            self.ws_app.close()
        super(KeeperPushNotifications, self).shutdown()
