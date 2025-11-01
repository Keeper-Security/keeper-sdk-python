from __future__ import annotations

import abc
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import sqlite3
from typing import Dict, Any, Optional, Callable, Tuple, List, Iterator
from urllib.parse import urlunparse, urlparse, urlencode
from uuid import getnode

import attrs
import requests
import websockets
from cryptography.hazmat.primitives.asymmetric import ec

from . import agent_storage, pedm_shared
from ... import utils, crypto, background
from ...storage import storage_types, in_memory


@attrs.define(kw_only=True)
class DeploymentToken:
    hostname: str
    deployment_uid: str
    private_key: bytes

@attrs.define(kw_only=True)
class AgentData:
    deployment_uid: Optional[str] = None
    hostname: str
    hash_key: bytes
    peer_public_key: bytes

    def to_dict(self) -> Dict[str, Any]:
        ad = {
            'hostname': self.hostname,
            'hash_key': utils.base64_url_encode(self.hash_key),
            'peer_public_key': utils.base64_url_encode(self.peer_public_key),
        }
        if self.deployment_uid:
            ad['deployment_uid'] = self.deployment_uid
        return ad

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgentData:
        return AgentData(deployment_uid=data.get('deployment_uid'), hostname=data['hostname'],
                         hash_key=utils.base64_url_decode(data['hash_key']),
                         peer_public_key=utils.base64_url_decode(data['peer_public_key']))

@attrs.define(kw_only=True)
class AgentConfiguration:
    agent_uid: str
    public_key: bytes
    private_key: bytes
    agent_data: Optional[AgentData] = None

    def to_dict(self) -> Dict[str, Any]:
        agent_config: Dict[str, Any] = {
            'agent_uid': self.agent_uid,
            'public_key': utils.base64_url_encode(self.public_key),
            'private_key': utils.base64_url_encode(self.private_key),
        }
        if self.agent_data:
            agent_config['agent_data'] = self.agent_data.to_dict()
        return agent_config

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgentConfiguration:
        agent_config = AgentConfiguration(agent_uid=data['agent_uid'],
                                          public_key=utils.base64_url_decode(data['public_key']),
                                          private_key=utils.base64_url_decode(data['private_key']))
        agent_data = data.get('agent_data')
        if isinstance(agent_data, dict):
            agent_config.agent_data = AgentData.from_dict(agent_data)
        return agent_config

class IAgentConfigurationStorage(abc.ABC):
    @abc.abstractmethod
    def load(self) -> AgentConfiguration:
        pass

    @abc.abstractmethod
    def store(self, agent: AgentConfiguration) -> None:
        pass


class JsonAgentConfigurationStorage(IAgentConfigurationStorage):
    def __init__(self, file_name: str):
        self.file_name = file_name

    def load(self) -> AgentConfiguration:
        file_name = os.path.expanduser(self.file_name)
        with open(file_name, 'rt') as f:
            j = json.load(f)
        return AgentConfiguration.from_dict(j)


    def store(self, agent: AgentConfiguration) -> None:
        file_name = os.path.expanduser(self.file_name)
        with open(file_name, 'wt') as f:
            json.dump(agent.to_dict(), f, indent=2)


@attrs.define(kw_only=True, frozen=True)
class PolicyInformation(storage_types.IUid[str]):
    policy_uid: str
    data: Dict[str, Any]
    def uid(self) -> str:
        return self.policy_uid

def create_agent() -> AgentConfiguration:
    agent_uid = utils.generate_uid()
    agent_private, agent_public = crypto.generate_ec_key()
    return AgentConfiguration(agent_uid=agent_uid, public_key=crypto.unload_ec_public_key(agent_public),
                              private_key=crypto.unload_ec_private_key(agent_private))


class PedmAgentPlugin:
    def __init__(self, config_storage: IAgentConfigurationStorage, *, get_connection: Optional[Callable[[], sqlite3.Connection]] = None):
        configuration = config_storage.load()
        self.config_storage = config_storage

        if not configuration.agent_uid:
            raise Exception('Agent config validation: missing agent UID')
        self.agent_uid = configuration.agent_uid

        if not configuration.private_key:
            raise Exception('Agent config validation: missing agent private key')
        self.private_key = crypto.load_ec_private_key(configuration.private_key)

        if not configuration.public_key:
            raise Exception('Agent config validation: missing agent public key')
        self.public_key = crypto.load_ec_public_key(configuration.public_key)

        self.peer_public_key: Optional[ec.EllipticCurvePublicKey] = None
        self.hash_key: Optional[bytes] = None
        self.hostname: Optional[str] = None
        self.deployment_uid: Optional[str] = None
        self._notifications: Optional[websockets.ClientConnection] = None

        if configuration.agent_data:
            if not configuration.agent_data.hostname:
                raise Exception('Agent config validation: missing hostname')
            self.hostname = configuration.agent_data.hostname

            if not configuration.agent_data.peer_public_key:
                raise Exception('Agent config validation: missing peer public key')
            self.peer_public_key = crypto.load_ec_public_key(configuration.agent_data.peer_public_key)

            if not configuration.agent_data.hash_key:
                raise Exception('Agent config validation: missing hash key')
            self.hash_key = configuration.agent_data.hash_key
            if configuration.agent_data.deployment_uid:
                self.deployment_uid = configuration.agent_data.deployment_uid

        self._get_connection: Optional[Callable[[], sqlite3.Connection]] = get_connection

        self._storage: agent_storage.IPedmAgentStorage
        if self._get_connection is None:
            self._storage = agent_storage.MemoryPedmAgentStorage()
        else:
            self._storage = agent_storage.SqlitePedmAgentStorage( self._get_connection, self.agent_uid)

        self._policies = in_memory.InMemoryEntityStorage[PolicyInformation, str]()
        if configuration.agent_data:
            self.sync_down()

    def close(self):
        self.stop_notifications()
        self._get_connection = None

    @property
    def storage(self) -> agent_storage.IPedmAgentStorage:
        assert self._storage is not None
        return self._storage

    @property
    def is_registered(self) -> bool:
        return self.peer_public_key is not None

    @property
    def policies(self) -> storage_types.IEntityReader[PolicyInformation, str]:
        return self._policies

    def store_agent_configuration(self) -> None:
        agent_data: Optional[AgentData] = None
        if self.is_registered:
            assert self.hostname
            assert self.peer_public_key
            assert self.hash_key

            agent_data = AgentData(deployment_uid=self.deployment_uid, hostname=self.hostname,
                           peer_public_key=crypto.unload_ec_public_key(self.peer_public_key), hash_key=self.hash_key)
        agent = AgentConfiguration(agent_uid=self.agent_uid, private_key=crypto.unload_ec_private_key(self.private_key),
                                   public_key=crypto.unload_ec_public_key(self.public_key), agent_data=agent_data)
        self.config_storage.store(agent)

    def register(self, token: DeploymentToken, force: bool = False) -> None:
        if self.is_registered and not force:
            raise Exception('Agent is already registered')

        deployment_uid = token.deployment_uid
        deployment_private_key = crypto.load_ec_private_key(token.private_key)
        agent_public_data = crypto.unload_ec_public_key(self.public_key)
        machine_id = str(getnode()).encode('ascii')
        machine_id = hmac.new(machine_id, b'machine id', hashlib.sha256).digest()
        payload = json.dumps({
            'agentUid': self.agent_uid,
            'agentPublicKey': utils.base64_url_encode(agent_public_data),
            'machineId': utils.base64_url_encode(machine_id),
        }).encode('utf-8')
        timestamp = utils.current_milli_time()

        signature = crypto.sign_ec(timestamp.to_bytes(8, byteorder='big') + payload, deployment_private_key)
        headers = {
            'Authorization': 'KeeperDeployment ' + deployment_uid,
            'Signature': base64.b64encode(signature).decode('ascii'),
            'Timestamp': str(timestamp),
            'Version': '1'
        }
        logger = utils.get_logger()
        if 'ROUTER_URL' in os.environ:
            up = urlparse(os.environ['ROUTER_URL'])
            url_comp = (up.scheme, up.netloc, 'api/agent/register', None, None, None)
        else:
            router_host = f'connect.{token.hostname}'
            url_comp = ('https', router_host, 'api/agent/register', None, None, None)
        url = urlunparse(url_comp)
        logger.debug('>>> [DEPLOYMENT] POST Request: [%s]', url)

        response = requests.post(url, headers=headers, data=payload)
        logger.debug('<<<  [DEPLOYMENT] Response Code: [%d]', response.status_code)
        if response.status_code != 200:
            message = response.reason
            content_type =  response.headers.get('Content-Type') or ''
            if content_type.startswith('text/'):
                message = response.text
            raise Exception(f'Router error ({response.status_code}): {message}')

        data = crypto.decrypt_ec(response.content, deployment_private_key)
        deployment_info = json.loads(data)
        if 'agentData' not in deployment_info:
            raise Exception('Register Agent: invalid response')
        agent_data = utils.base64_url_decode(deployment_info['agentData'])
        agent_data = crypto.decrypt_ec(agent_data, deployment_private_key)
        deployment = pedm_shared.DeploymentAgentInformation.from_dict(json.loads(agent_data))

        self.deployment_uid = deployment_uid
        self.hostname = token.hostname
        self.peer_public_key = crypto.load_ec_public_key(deployment.peer_public_key)
        self.hash_key = deployment.hash_key
        self.store_agent_configuration()

        self.sync_down(reload=True)

    def unregister(self) -> None:
        if not self.is_registered:
            raise Exception('Agent is not registered')
        self.execute_rest('unregister')
        self._policies.clear()
        self._storage.reset()

        self.peer_public_key = None
        self.hash_key = None
        self.hostname = None
        self.deployment_uid = None
        self.store_agent_configuration()
        self.close()

    def ping(self) -> None:
        self.execute_rest('ping')
        # self.sync_down()

    def execute_rest(self, endpoint: str, request: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        if not self.is_registered:
            raise Exception('Agent is not registered')

        logger = utils.get_logger()
        body = json.dumps(request) if request is not None else ''
        timestamp = utils.current_milli_time()
        signature = crypto.sign_ec(timestamp.to_bytes(8, byteorder='big') + body.encode('utf-8'), self.private_key)
        headers: Dict[str, str] = {
            'Authorization': f'KeeperAgent {self.agent_uid}',
            'Signature': base64.b64encode(signature).decode('ascii'),
            'Timestamp': str(timestamp),
            'Version': '1'
        }
        if 'ROUTER_URL' in os.environ:
            up = urlparse(os.environ['ROUTER_URL'])
            url_comp = (up.scheme, up.netloc, f'api/agent/{endpoint}', None, None, None)
        else:
            hostname = f'connect.{self.hostname}'
            url_comp = ('https', hostname, f'api/agent/{endpoint}', None, None, None)
        url = urlunparse(url_comp)

        logger.debug('>>> [AGENT] POST Request: [%s]', url)
        logger.debug('>>> [AGENT] [RQ] \"%s\": %s', endpoint, body)
        headers['Content-Type'] = 'application/json' if request else 'text/plain'
        response = requests.post(url, headers=headers, data=body)
        logger.debug('<<<  [AGENT] Response Code: [%d]', response.status_code)

        content_type: str = response.headers.get('Content-Type') or ''
        if response.status_code >= 300:
            if content_type.startswith('text/plain'):
                raise Exception(f'Router error ({response.status_code}): {response.text}')
            raise Exception(f'Router status code: {response.status_code}')
        else:
            if content_type.startswith('application/octet-stream'):
                data = crypto.decrypt_ec(response.content, self.private_key).decode('utf-8')
                if data:
                    json_rs = json.loads(data)
                    if logger.level <= logging.DEBUG:
                        logger.debug('>>> [AGENT] [RS] \"%s\": %s', endpoint, data[:1000])
                    return json_rs
            elif content_type.startswith('text/plain'):
                text_rs = response.text
                if logger.level <= logging.DEBUG:
                    logger.debug('>>> [AGENT] [RS] \"%s\": %s', endpoint, text_rs)
        return None

    def get_hashed_value(self, field_id: str, value: str) -> Tuple[str, bytes]:
        if not self.is_registered:
            raise Exception('Agent is not registered')
        assert self.hash_key is not None
        assert self.peer_public_key is not None

        message = f'{field_id}:{value.strip().lower()}'.encode('utf-8')
        d = hmac.new(self.hash_key, message, hashlib.sha256).digest()
        x1 = int.from_bytes(d[:16], byteorder='big', signed=False)
        x2 = int.from_bytes(d[16:], byteorder='big', signed=False)
        value_uid = utils.base64_url_encode((x1 ^ x2).to_bytes(length=16, byteorder='big', signed=False))
        encrypted_data = crypto.encrypt_ec(value.encode('utf-8'), self.peer_public_key)

        return value_uid, encrypted_data

    def get_collection_value_hash(self, collection_type: int, collection_value: str) -> str:
        if not self.is_registered:
            raise Exception('Agent is not registered')
        assert self.hash_key is not None
        message = collection_type.to_bytes(length=4, byteorder='big', signed=False)
        message += collection_value.lower().encode('utf-8')
        d = hmac.new(self.hash_key, message, hashlib.sha256).digest()
        x1 = int.from_bytes(d[:16], byteorder='big', signed=False)
        x2 = int.from_bytes(d[16:], byteorder='big', signed=False)
        return utils.base64_url_encode((x1 ^ x2).to_bytes(length=16, byteorder='big', signed=False))

    def load_collections(self, collections_uid: List[str] ) -> Iterator[agent_storage.PedmAgentCollection]:
        if not self.is_registered:
            raise Exception('Agent is not registered')
        assert self.hash_key is not None

        if not collections_uid:
            return

        while len(collections_uid) > 0:
            chunk =  collections_uid[:500]
            collections_uid = collections_uid[500:]
            rq = {
                'collection_uid': chunk,
            }
            rs = self.execute_rest('get_collections', rq)
            if isinstance(rs, dict):
                collections = rs.get('collections')
                if isinstance(collections, list):
                    for collection in collections:
                        collection_uid = collection.get('collection_uid')
                        collection_type = collection.get('collection_type')
                        collection_data = collection.get('collection_data')
                        data: bytes = b''
                        if collection_data:
                            try:
                                data = utils.base64_url_decode(collection_data)
                                data = crypto.decrypt_aes_v2(data, self.hash_key)
                            except:
                                pass
                        yield agent_storage.PedmAgentCollection(
                            collection_uid=collection_uid, collection_type=collection_type, data=data)

    def load_agent_collections(self) -> None:
        # TODO refactor to use get_recourses + get_collections
        if not self.is_registered:
            raise Exception('Agent is not registered')
        assert self.hash_key is not None

        resources: List[str] = []
        has_more = True
        from_resource_uid: Optional[str] = None
        while has_more:
            has_more = False
            rq = {
                'from_resource_uid': from_resource_uid,
            }
            rs = self.execute_rest('get_resources', rq)
            assert rs is not None
            from_resource_uid = None
            if isinstance(rs, dict):
                has_more = rs.get('has_more') is True
                if has_more:
                    from_resource_uid = rs.get('next_resource_uid')
            rs_resources = rs.get('resources')
            if isinstance(rs_resources, list):
                for resource in rs_resources:
                    if isinstance(resource, dict):
                        resource_uid = resource.get('resource_uid')
                        if resource_uid:
                            resources.append(resource_uid)

        collections = list(self.load_collections(resources))
        if len(collections) > 0:
            self.storage.collections.put_entities(collections)

    def sync_down(self, *, reload: bool = False) -> None:
        assert self._storage

        logger = utils.get_logger('keeper.pedm')

        if reload is True:
            self._storage.reset()

        settings = self._storage.settings.load()
        if settings is None:
            settings = agent_storage.PedmAgentSettings(token=b'')

        policies_to_put: List[agent_storage.PedmAgentPolicy] = []
        policies_to_remove: List[str] = []

        approvals_to_put: List[agent_storage.PedmAgentApproval] = []
        approval_status_to_put: List[agent_storage.PedmAgentApprovalStatus] = []
        approvals_to_remove: List[str] = []

        sync_token: Optional[str] = None
        if settings.token:
            sync_token = utils.base64_url_encode(settings.token)

        sync_rq: Dict[str, Any] = {}
        done = False
        while not done:
            if sync_token:
                sync_rq['token'] = sync_token
            sync_rs = self.execute_rest('sync_down', sync_rq)
            assert sync_rs is not None

            done = sync_rs.get('has_more') is not True
            sync_token = sync_rs.get('token')
            assert isinstance(sync_token, str)

            agent_info = sync_rs.get('agent_info')
            if isinstance(agent_info, dict):
                deployment_uid = agent_info.get('deployment_uid')
                if deployment_uid:
                    if self.deployment_uid != deployment_uid:
                        self.deployment_uid = deployment_uid
                        self.store_agent_configuration()

            policies = sync_rs.get('policy_data')
            if isinstance(policies, list) and len(policies) > 0:
                for policy_data in policies:
                    if not isinstance(policy_data, dict):
                        continue
                    uid: Optional[str] = policy_data.get('policy_uid')
                    data: Optional[str] = policy_data.get('policy_data')
                    key: Optional[str] = policy_data.get('policy_key')
                    disabled: bool = policy_data.get('disabled') is True
                    if uid and data and key:
                        policy = agent_storage.PedmAgentPolicy(
                            policy_uid=uid, data=utils.base64_url_decode(data), key=utils.base64_url_decode(key),
                            disabled=disabled)
                        policies_to_put.append(policy)

            removed_policy = sync_rs.get('removed_policy')
            if isinstance(removed_policy, list) and len(removed_policy) > 0:
                policies_to_remove.extend(removed_policy)

            approvals = sync_rs.get('approval')
            if isinstance(approvals, list) and len(approvals) > 0:
                for approval in approvals:
                    if not isinstance(approval, dict):
                        continue
                    approval_uid: Any = approval.get('approval_uid')
                    approval_type: Any = approval.get('approval_type')
                    account_info: Any = approval.get('account_info')
                    application_info: Any = approval.get('application_info')
                    justification: Any = approval.get('justification')
                    expire_in: Any = approval.get('expire_in')
                    created = approval.get('created')
                    if not isinstance(created, int):
                        created = 0

                    approvals_to_put.append(agent_storage.PedmAgentApproval(
                        approval_uid=approval_uid, approval_type=approval_type,
                        account_info=utils.base64_url_decode(account_info),
                        application_info=utils.base64_url_decode(application_info),
                        justification=utils.base64_url_decode(justification),
                        expire_in=expire_in, created=created,
                    ))

            approval_statuses = sync_rs.get('approval_status')
            if isinstance(approval_statuses, list) and len(approval_statuses) > 0:
                for status in approval_statuses:
                    if not isinstance(status, dict):
                        continue
                    approval_uid = status.get('approval_uid')
                    approval_status: Any = status.get('approval_status')
                    modified = status.get('modified')
                    if not isinstance(modified, int):
                        modified = 0
                    approval_status_to_put.append(agent_storage.PedmAgentApprovalStatus(
                        approval_uid=approval_uid, approval_status=approval_status, modified=modified
                    ))


            removed_approval = sync_rs.get('removed_approval')
            if isinstance(removed_approval, list) and len(removed_approval) > 0:
                approvals_to_remove.extend(removed_approval)

        if sync_token:
            settings.token = utils.base64_url_decode(sync_token)
            self.storage.settings.store(settings)

        if len(policies_to_remove) > 0:
            self.storage.policies.delete_uids(policies_to_remove)

        if len(policies_to_put) > 0:
            self.storage.policies.put_entities(policies_to_put)

        if len(approvals_to_put) > 0:
            self.storage.approvals.put_entities(approvals_to_put)

        if len(approval_status_to_put) > 0:
            self.storage.approval_status.put_entities(approval_status_to_put)

        if len(approvals_to_remove) > 0:
            self.storage.approval_status.delete_uids(approvals_to_remove)
            self.storage.approvals.delete_uids(approvals_to_remove)

        # TODO reload policies
        self._policies.clear()
        assert self.hash_key
        for policy in self.storage.policies.get_all_entities():
            try:
                if policy.data and policy.key:
                    policy_key = crypto.decrypt_aes_v2(policy.key, self.hash_key)
                    policy_data = crypto.decrypt_aes_v2(policy.data, policy_key)
                    p_data = json.loads(policy_data)
                    p = PolicyInformation(policy_uid=policy.policy_uid, data=p_data)
                    self._policies.put_entities([p])
            except Exception as e:
                logger.warning('Policy "%s" decryption error: %s', policy.policy_uid, e)

    def start_notifications(self):
        if not self.is_registered:
            raise Exception('Agent is not registered')

        self.stop_notifications()
        asyncio.run_coroutine_threadsafe(self.notification_main_loop(), loop=background.get_loop())

    def stop_notifications(self):
        if self._notifications:
            if self._notifications.state == websockets.State.OPEN:
                try:
                    asyncio.run_coroutine_threadsafe(self._notifications.close(), loop=background.get_loop()).result(timeout=1.0)
                except:
                    utils.get_logger().debug('Failed to close websocket connection')
            self._notifications = None

    async def notification_main_loop(self) -> None:
        logger = utils.get_logger()
        token = utils.generate_uid()
        timestamp = utils.current_milli_time()
        signature = crypto.sign_ec(timestamp.to_bytes(8, byteorder='big') + token.encode('utf-8'), self.private_key)
        headers: Dict[str, str] = {
            'Authorization': f'KeeperAgent {self.agent_uid}',
            'Signature': base64.b64encode(signature).decode('ascii'),
            'Timestamp': str(timestamp),
        }
        query = urlencode({
            'token': token
        })
        if 'ROUTER_URL' in os.environ:
            up = urlparse(os.environ['ROUTER_URL'])
            scheme = 'wss' if up.scheme == 'https' else 'ws'
            url_comp = (scheme, up.netloc, 'api/agent/connect', None, query, None)
        else:
            hostname = f'connect.{self.hostname}'
            url_comp = ('wss', hostname, 'api/agent/connect', None, query, None)
        url = str(urlunparse(url_comp))
        # ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        try:
            async with websockets.connect(url, additional_headers=headers, ping_interval=30, open_timeout=4) as ws_app:
                self._notifications = ws_app
                async for message in ws_app:
                    if isinstance(message, bytes):
                        try:
                            pass
                        except Exception as e:
                            logger.debug('Push notification: decrypt error: ', e)
        except Exception as e:
            logger.debug('Push notification: exception: %s', e)
        logger.debug('Exit Push notification')
