from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import sqlite3
from typing import Dict, Any, Optional, Callable
from urllib.parse import urlunparse

import attrs
import requests
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

from . import pedm_constants, agent_storage
from ... import utils, crypto
from ...storage import dag, in_memory, storage_types


@attrs.define(kw_only=True)
class KsmConfiguration:
    client_id: str
    private_key: bytes
    hostname: str
    database_name: str = ''

    @staticmethod
    def parse(config: Dict[str, Any]) -> KsmConfiguration:
        private_key = base64.b64decode(config['privateKey'])
        client_id: Optional[str] = config['clientId']
        assert client_id is not None
        return KsmConfiguration(client_id=client_id, private_key=private_key, hostname=config['hostname'])


@attrs.define(kw_only=True)
class ControllerInfo:
    enterprise_id: int
    owner_id: int
    controller_uid: str
    controller_name: str = ''
    policy_endpoint_uid: str
    log_endpoint_uid: str
    device_uid: str


class PedmAgentPlugin:
    def __init__(self, configuration: KsmConfiguration, *, get_connection: Optional[Callable[[], sqlite3.Connection]] = None):
        self.configuration = configuration
        self.server = f'connect.{configuration.hostname}'
        pk = serialization.load_der_private_key(self.configuration.private_key, password=None, backend=backends.default_backend())
        assert isinstance(pk, ec.EllipticCurvePrivateKey)
        self.private_key: ec.EllipticCurvePrivateKey = pk
        self._get_connection: Optional[Callable[[], sqlite3.Connection]] = get_connection
        self._storage: Optional[agent_storage.IPedmAgentStorage] = None
        self._controller_info: Optional[ControllerInfo] = None
        self._policies = in_memory.InMemoryEntityStorage[agent_storage.PolicyInformation, str]()

    @property
    def storage(self) -> agent_storage.IPedmAgentStorage:
        assert self._storage is not None
        return self._storage

    def connect(self) -> None:
        c_info = self.execute_rest('controller_info')
        assert isinstance(c_info, dict)
        controller_uid: Optional[str] = c_info['controllerUid']
        assert controller_uid is not None

        hm = hmac.new(utils.base64_url_decode(pedm_constants.AGENT_KEY), digestmod=hashlib.sha256)
        hm.update(base64.b64decode(controller_uid))
        controller_hash = hm.digest()

        policy_endpoint_uid = utils.base64_url_encode(controller_hash[:16])
        log_endpoint_uid = utils.base64_url_encode(controller_hash[16:])

        if self._get_connection is None:
            self._storage = agent_storage.MemoryPedmAgentStorage()
        else:
            self._storage = agent_storage.SqlitePedmAgentStorage( self._get_connection, controller_uid)

        self._controller_info = ControllerInfo(
            enterprise_id=c_info['enterpriseId'], owner_id=c_info['ownerId'], controller_uid=controller_uid,
            controller_name=c_info['controllerName'], policy_endpoint_uid=policy_endpoint_uid,
            log_endpoint_uid=log_endpoint_uid, device_uid=utils.generate_uid())
        self.sync_down()

        # TODO Web socket
    @property
    def policies(self) -> storage_types.IEntity[agent_storage.PolicyInformation, str]:
        return self._policies

    def disconnect(self) -> None:
        self._controller_info = None
        self._storage = None

    def execute_rest(self, endpoint: str, request: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        logger = utils.get_logger()

        url_comp = ('https', self.server, 'api/device/get_challenge', None, None, None)
        url = urlunparse(url_comp)
        response = requests.get(url)
        challenge = response.text

        to_sign = base64.b64decode(self.configuration.client_id) + base64.b64decode(challenge)
        signature = self.private_key.sign(to_sign, ec.ECDSA(algorithm=hashes.SHA256()))

        headers: Dict[str, str] = {
            'Authorization': f'KeeperDevice {self.configuration.client_id}',
            'Challenge': challenge,
            'Signature': base64.b64encode(signature).decode('ascii'),
            'ClientVersion': 'ms16.2.4',
        }

        url_comp = ('https', self.server, f'api/device/{endpoint}', None, None, None)
        url = urlunparse(url_comp)

        if request is None:
            logger.debug('>>> [AGENT] GET Request: [%s]', url)
            response = requests.get(url, headers=headers)
        else:
            logger.debug('>>> [AGENT] POST Request: [%s]', url)
            body = json.dumps(request)
            logger.debug('>>> [AGENT] [RQ] \"%s\": %s', endpoint, body)
            headers['Content-Type'] = 'application/json'
            response = requests.post(url, headers=headers, data=body)
        logger.debug('<<<  [AGENT] Response Code: [%d]', response.status_code)

        content_type: str = response.headers.get('Content-Type') or ''
        if response.status_code >= 300:
            if content_type.endswith('/text'):
                raise Exception(f'Router error ({response.status_code}): {response.text}')
            raise Exception(f'Router status code: {response.status_code}')
        else:
            if content_type == 'application/json':
                json_rs = response.json()
                if logger.level <= logging.DEBUG:
                    js = json.dumps(json_rs)
                    logger.debug('>>> [AGENT] [RS] \"%s\": %s', endpoint, js)
                return json_rs


    def sync_down(self, *, reload: bool = False) -> None:
        assert self._storage
        assert self._controller_info

        logger = utils.get_logger('keeper.pedm')

        if reload is True:
            self._storage.reset()

        settings = self._storage.settings.load()
        if settings is None:
            settings = agent_storage.PedmAgentSettings(sync_point=0)

        policies_to_update: Dict[str, agent_storage.PedmAgentPolicy] = {}
        policy: Optional[agent_storage.PedmAgentPolicy]

        sync_point = settings.sync_point
        sync_rq = dag.DagSyncRequest(
            graph_id=pedm_constants.PEDM_GRAPH_ID, stream_id=self._controller_info.policy_endpoint_uid,
            device_id=self._controller_info.device_uid)

        done = False
        while not done:
            sync_rq.sync_point = sync_point
            sync_rs = self.execute_rest('sync', sync_rq.to_dict())
            assert sync_rs is not None

            done = not (sync_rs.get('hasMore') is True)
            sp = sync_rs.get('syncPoint')
            if isinstance(sp, int):
                sync_point = sp
            data = sync_rs.get('data')
            if isinstance(data, list):
                for e in data:
                    try:
                        edge = dag.DagEdge.parse(e)
                        if not edge:
                            continue
                        if not edge.content:
                            continue

                        json_data = json.loads(edge.content)
                        if not isinstance(json_data, dict):
                            raise ValueError(f'Invalid edge content')

                        if edge.parentRef is None:
                            if 'entity_type' not in json_data:
                                raise ValueError('Edge content does not contain entity_type')
                            entity_type = json_data.get('entity_type')
                            if entity_type != pedm_constants.POLICY_DB_TYPE:
                                raise ValueError(f'Invalid entity type: {entity_type}')
                            entity_uid = edge.ref.value

                            policy = policies_to_update.get(entity_uid)
                            if policy is None:
                                policy = self._storage.policies.get_entity(entity_uid)
                            if policy is None:
                                policy = agent_storage.PedmAgentPolicy(policy_uid=entity_uid)
                                policies_to_update[entity_uid] = policy

                            if edge.type == dag.EdgeType.DATA:
                                if 'encrypted_data' not in json_data:
                                    raise ValueError('Edge content does not contain encrypted_data')
                                content = utils.base64_url_decode(json_data['encrypted_data'])
                                policy.data = content
                            elif edge.type == dag.EdgeType.DELETION:
                                policy.data = b''
                            else:
                                raise ValueError(f'Invalid entity edge type: {edge.type}')
                        else:
                            if 'link_type' not in json_data:
                                raise ValueError('Edge content does not contain link_type')
                            link_type = json_data.get('link_type')
                            if link_type != pedm_constants.POLICY_KEY_DB_TYPE:
                                raise ValueError(f'Invalid link type: {link_type}')
                            subject_uid = edge.ref.value
                            object_uid = edge.parentRef.value

                            policy = policies_to_update.get(subject_uid)
                            if policy is None:
                                policy = self._storage.policies.get_entity(subject_uid)
                            if policy is None:
                                policy = agent_storage.PedmAgentPolicy(policy_uid=subject_uid)
                                policies_to_update[subject_uid] = policy

                            if object_uid == self._controller_info.policy_endpoint_uid:
                                if edge.type == dag.EdgeType.KEY:
                                    if 'encrypted_key' not in json_data:
                                        raise ValueError('Edge content does not contain encrypted_key')
                                    content = utils.base64_url_decode(json_data['encrypted_key'])
                                    policy.key = content
                                elif edge.type == dag.EdgeType.DELETION:
                                    policy.key = b''
                                else:
                                    raise ValueError(f'Invalid link edge type: {edge.type}')
                            else:
                                raise ValueError(f'Invalid link edge parent UID: {object_uid}')
                    except Exception as e:
                        logger.warning(f'"DagEdge" parse error: {e}')

        if settings.sync_point == sync_point:
            return

        settings.sync_point = sync_point
        self.storage.settings.store(settings)

        to_delete = {x.policy_uid for x in policies_to_update.values() if not x.data and not x.key}
        for policy_uid in to_delete:
            del policies_to_update[policy_uid]

        if len(policies_to_update) > 0:
            self.storage.policies.put_entities(policies_to_update.values())
        if len(to_delete) > 0:
            self.storage.policies.delete_uids(to_delete)

        self._policies.clear()
        for policy in self.storage.policies.get_all_entities():
            try:
                if policy.data and policy.key:
                    policy_key = crypto.decrypt_ec(policy.key, self.private_key)
                    policy_data = crypto.decrypt_aes_v2(policy.data, policy_key)
                    data = json.loads(policy_data)
                    assert isinstance(data, dict)
                    policy_name = data.get('displayname') or policy.policy_uid
                    p = agent_storage.PolicyInformation(policy_uid=policy.policy_uid, name=policy_name, data=data)
                    self._policies.put_entities([p])
            except Exception as e:
                logger.warning(f'Policy "%s" decryption error: %s', policy.policy_uid, e)

    def post_logs(self, content: bytes) -> None:
        assert self._controller_info
        ref = dag.Ref(type=dag.RefType.DEVICE, value=self._controller_info.log_endpoint_uid)
        edge = dag.DagEdge(type=dag.EdgeType.DATA, ref=ref, path=utils.generate_uid(), content=content)
        origin = dag.Ref(type=dag.RefType.DEVICE, value=self._controller_info.device_uid)
        add_rq = dag.DagAddRequest(graph_id=pedm_constants.PEDM_GRAPH_ID, origin=origin, data_list=[edge])
        rs = self.execute_rest('add_data', add_rq.to_dict())
        if rs is not None:
            print(rs)
