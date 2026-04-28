
import csv
from enum import Enum
import logging
import sys
import time
import os
from pydantic import BaseModel
from typing import Any, Dict, Optional, Tuple, Union

from . import dag_utils, dag_crypto, exceptions
from .dag_types import SyncQuery
from .__version__ import __version__ as dag_version

from ...proto import router_pb2, GraphSync_pb2

class ConnectionBase:

    ADD_DATA = "/add_data"
    SYNC = "/sync"

    TIMEOUT = 30

    def __init__(self,
                 is_device: bool,
                 logger: Optional[logging.Logger] = None,
                 log_transactions: Optional[bool] = None,
                 log_transactions_dir: Optional[str] = None,
                 use_read_protobuf: bool = False,
                 use_write_protobuf: bool = False):

        self.is_device = is_device

        if logger is None:
            logger = logging.getLogger()
        self.logger = logger

        if log_transactions is not None:
            self.log_transactions = dag_utils.value_to_boolean(log_transactions)
        else:
            self.log_transactions: bool = dag_utils.value_to_boolean(os.environ.get("GS_LOG_TRANS", False))

        self.log_transactions_dir = os.environ.get("GS_LOG_TRANS_DIR", log_transactions_dir)
        if self.log_transactions_dir is None:
            self.log_transactions_dir = "."

        if self.log_transactions is True:
            self.logger.info("keeper-dag transaction logging is ENABLED; "
                             f"write directory at {self.log_transactions_dir}")

        self.use_read_protobuf = use_read_protobuf
        self.use_write_protobuf = use_write_protobuf

        self.transmission_key = None

    def close(self):
        if hasattr(self, "logger"):
            self.logger = None
            del self.logger

    def __del__(self):
        self.close()

    def log_transaction_path(self, file: str):
        return os.path.join(self.log_transactions_dir, f"graph_{file}.csv")

    @staticmethod
    def get_record_uid(record: object) -> str:
        pass

    @staticmethod
    def get_key_bytes(record: object) -> bytes:
        pass

    @staticmethod
    def get_encrypted_payload_data(encrypted_payload_data: bytes) -> bytes:
        try:
            router_response = router_pb2.RouterResponse()
            router_response.ParseFromString(encrypted_payload_data)
            return router_response.encryptedPayload
        except Exception as err:
            raise Exception(f"Could not parse router response: {err}")

    def rest_call_to_router(self,
                            http_method: str,
                            endpoint: str,
                            agent: str,
                            payload: Optional[Union[str, bytes]] = None,
                            retry: int = 5,
                            retry_wait: float = 10,
                            throttle_inc_factor: float = 1.5,
                            timeout: Optional[int] = None,
                            headers: Optional[Dict] = None) -> Optional[bytes]:
        return b""

    def _endpoint(self, action: str, endpoint: Optional[str] = None) -> str:

        """
        Build the endpoint on the remote site.

        This method will attempt to fix slashes.

        :param action:
        :param endpoint:
        :return:
        """

        if endpoint is not None and endpoint != "":
            if isinstance(endpoint, Enum):
                endpoint = endpoint.value

            while endpoint.startswith("/"):
                endpoint = endpoint[1:]
            while endpoint.endswith("/"):
                endpoint = endpoint[:-1]
            endpoint = "/" + endpoint
        else:
            endpoint = ""

        while action.startswith("/"):
            action = action[1:]
        while action.endswith("/"):
            action = action[:-1]
        action = "/" + action

        base = "/api/device"
        if not self.is_device:
            base = "/api/user"

        return base + endpoint + action

    def write_transaction_log(self,
                              agent: str,
                              endpoint: str,
                              graph_id: Optional[int] = None,
                              request: Optional[Any] = None,
                              response: Optional[Any] = None,
                              error: Optional[str] = None):

        if self.log_transactions is True:

            file_name = graph_id
            if file_name is None:
                file_name = endpoint.replace("/", "_")

            timestamp = time.time()

            if isinstance(request, BaseModel):
                request = request.model_dump_json()
            elif hasattr(request, "SerializeToString"):
                request = request.SerializeToString()

            if isinstance(response, BaseModel):
                response = request.model_dump_json()
            elif hasattr(response, "SerializeToString"):
                response = request.SerializeToString()

            self.logger.info(f"TRANSACTION TIMESTAMP: {timestamp}")
            filename = self.log_transaction_path(str(file_name))
            self.logger.debug(f"write to {filename}")
            with open(filename, mode='a', newline='') as file:
                self.logger.debug("write add_data to transaction log")
                writer = csv.writer(file)
                writer.writerow([
                    timestamp,
                    sys.argv[0],
                    endpoint,
                    agent,
                    request,
                    response,
                    error
                ])
                file.close()

    def payload_and_headers(self, payload: Any) -> Tuple[Union[str, bytes], Dict]:

        headers = {}
        if isinstance(payload, BaseModel):
            self.logger.debug("payload is pydantic")
            payload = payload.model_dump_json()
        elif hasattr(payload, "SerializeToString"):
            self.logger.debug("payload is protobuf")
            headers = {'Content-Type': 'application/octet-stream'}
            payload = dag_crypto.encrypt_aes(payload.SerializeToString(), self.transmission_key)
        else:
            raise Exception("Cannot determine if the model is pydantic or protobuf.")

        return payload, headers

    def sync(self,
             sync_query: Union[SyncQuery, GraphSync_pb2.GraphSyncQuery],
             graph_id: Optional[int] = None,
             endpoint: Optional[str] = None,
             agent: Optional[str] = None) -> bytes:

        if agent is None:
            f"keeper-dag/{dag_version}"

        endpoint = self._endpoint(ConnectionBase.SYNC, endpoint)
        self.logger.debug(f"endpoint {endpoint}")

        try:
            sync_query, headers = self.payload_and_headers(sync_query)
            payload = self.rest_call_to_router(http_method="POST",
                                               endpoint=endpoint,
                                               agent=agent,
                                               headers=headers,
                                               payload=sync_query)

            if self.use_read_protobuf:
                try:
                    self.logger.debug(f"decrypt payload with transmission key {dag_utils.kotlin_bytes(self.transmission_key)}")
                    payload = self.get_encrypted_payload_data(payload)
                    payload = dag_crypto.decrypt_aes(payload, self.transmission_key)
                except Exception as err:
                    self.logger.error(f"Could not decrypt protobuf graph sync response: {type(err)}, {err}")

            self.write_transaction_log(
                graph_id=graph_id,
                request=sync_query,
                response=payload,
                agent=agent,
                endpoint=endpoint,
                error=None
            )

            return payload

        except exceptions.DAGConnectionException as err:

            self.write_transaction_log(
                graph_id=graph_id,
                request=sync_query,
                response=None,
                agent=agent,
                endpoint=endpoint,
                error=str(err)
            )
            raise err
        except Exception as err:
            self.write_transaction_log(
                graph_id=graph_id,
                request=sync_query,
                response=None,
                agent=agent,
                endpoint=endpoint,
                error=str(err)
            )
            raise exceptions.DAGException(f"Could not load the DAG structure: {err}")

    def debug_dump(self) -> str:
        return "Connection does not allow debug dump."

    def add_data(self,
                 payload: Union[dag_types.DataPayload, GraphSync_pb2.GraphSyncAddDataRequest],
                 graph_id: Optional[int] = None,
                 endpoint: Optional[str] = None,
                 use_protobuf: bool = False,
                 agent: Optional[str] = None):

        if agent is None:
            f"keeper-dag/{dag_version}"

        endpoint = self._endpoint(ConnectionBase.ADD_DATA, endpoint)
        self.logger.debug(f"endpoint {endpoint}")

        try:
            payload, headers = self.payload_and_headers(payload)
            self.rest_call_to_router(http_method="POST",
                                     endpoint=endpoint,
                                     payload=payload,
                                     headers=headers,
                                     agent=agent)

            self.write_transaction_log(
                graph_id=graph_id,
                request=payload,
                response=None,
                agent=agent,
                endpoint=endpoint,
                error=None
            )
        except exceptions.DAGConnectionException as err:
            self.write_transaction_log(
                graph_id=graph_id,
                request=payload,
                response=None,
                agent=agent,
                endpoint=endpoint,
                error=str(err)
            )
            raise err
        except Exception as err:
            self.write_transaction_log(
                graph_id=graph_id,
                request=payload,
                response=None,
                agent=agent,
                endpoint=endpoint,
                error=str(err)
            )
            raise exceptions.DAGException(f"Could not create a new DAG structure: {err}")
