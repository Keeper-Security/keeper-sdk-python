import hashlib
import hmac
import json
from typing import Dict, Set, Tuple, Iterator, Any, Iterable, List, Optional

import attrs

from . import pedm_storage, pedm_constants, pedm_types
from ... import crypto, utils
from ...enterprise import enterprise_loader, sqlite_enterprise_storage
from ...proto import pam_pb2, enterprise_pb2, APIRequest_pb2
from ...storage import dag, storage_types, in_memory


@attrs.define(frozen=True)
class _PedmAgent(pedm_types.PedmAgent):
    pass

@attrs.define(frozen=True)
class _PedmPolicy(pedm_types.PedmPolicy):
    pass

@attrs.define(frozen=True)
class _PedmOrganizationUnit(pedm_types.PedmOrganizationUnit):
    pass


class PedmPlugin:
    def __init__(self, loader: enterprise_loader.EnterpriseLoader):
        assert loader.keeper_auth.auth_context.enterprise_id
        hm = hmac.new(utils.base64_url_decode(pedm_constants.ENTERPRISE_KEY), digestmod=hashlib.sha256)
        hm.update(loader.keeper_auth.auth_context.enterprise_id.to_bytes(16, byteorder='big'))
        enterprise_hash = hm.digest()
        self.enterprise_uid: str = utils.base64_url_encode(enterprise_hash[:16])
        loader_storage = loader.storage
        self.storage: pedm_storage.IPedmStorage
        if isinstance(loader_storage, sqlite_enterprise_storage.SqliteEnterpriseStorage):
            self.storage = pedm_storage.SqlitePedmStorage(loader_storage.get_connection, loader_storage.enterprise_id)
        else:
            self.storage = pedm_storage.MemoryPedmStorage()
        self.loader = loader
        self.device_uid = utils.generate_uid()
        self._agents = in_memory.InMemoryEntityStorage[pedm_types.PedmAgent, str]()
        self._populate_agents = True
        self._policies = in_memory.InMemoryEntityStorage[pedm_types.PedmPolicy, str]()
        self._units = in_memory.InMemoryEntityStorage[pedm_types.PedmOrganizationUnit, str]()
        data: Dict[str, Any] = {'displayname': loader.enterprise_data.enterprise_info.enterprise_name}
        self._enterprise_unit = pedm_types.PedmOrganizationUnit(
            ou_uid=self.enterprise_uid, parent_ou_uid='', data=data, agents=set(), children_ou=set())

    @property
    def agents(self) -> storage_types.IEntity[pedm_types.PedmAgent, str]:
        return self._agents

    @property
    def units(self) -> storage_types.IEntity[pedm_types.PedmOrganizationUnit, str]:
        return self._units

    @property
    def policies(self) -> storage_types.IEntity[pedm_types.PedmPolicy, str]:
        return self._policies

    @property
    def enterprise_unit(self):
        return self._enterprise_unit

    def build_data(self) -> None:
        logger = utils.get_logger()
        self._enterprise_unit.agents = set()
        self._enterprise_unit.children_ou = set()

        agent_streams: Dict[str, str] = {}
        for agent in self._agents.get_all_entities():
            if not agent.public_key:
                continue
            agent_streams[agent.egress_uid] = agent.agent_uid

        tree_key = self.loader.enterprise_data.enterprise_info.tree_key
        policy_keys = {x.policy_uid: x.policy_key for x in self._policies.get_all_entities() if x.policy_key}
        agents = {x.agent_uid for x in self._agents.get_all_entities()}
        policy_agents: Dict[str, Set[str]] = {}
        unit_tree: Dict[str, Set[str]] = {}
        unit_agents: Dict[str, Set[str]] = {}
        for link in self.storage.links.get_all_links():
            if link.link_type == pedm_constants.POLICY_KEY_DB_TYPE:
                policy_uid = link.entity_uid
                agent_uid = link.parent_uid
                if agent_uid == self.enterprise_uid:
                    if policy_uid in policy_keys:
                        continue
                    try:
                        key = crypto.decrypt_aes_v2(link.data, tree_key)
                        policy_keys[policy_uid] = key
                    except Exception as e:
                        logger.debug('Policy "%s" key decryption error: %s', policy_uid, e)
                else:
                    if agent_uid in agent_streams:
                        agent_uid = agent_streams[agent_uid]
                    if agent_uid in agents:
                        if policy_uid not in policy_agents:
                            policy_agents[policy_uid] = set()
                        policy_agents[policy_uid].add(agent_uid)

            elif link.link_type == pedm_constants.UNIT_PARENT_DB_TYPE:
                child_ou_uid = link.entity_uid
                parent_ou_uid = link.parent_uid
                if parent_ou_uid not in unit_tree:
                    unit_tree[parent_ou_uid] = set()
                unit_tree[parent_ou_uid].add(child_ou_uid)

            elif link.link_type == pedm_constants.AGENT_UNIT_DB_TYPE:
                agent_uid = link.entity_uid
                if agent_uid not in agents:
                    continue
                uo_uid = link.parent_uid
                if uo_uid not in unit_agents:
                    unit_agents[uo_uid] = set()
                unit_agents[uo_uid].add(agent_uid)

        policies: Dict[str, pedm_types.PedmPolicy] = {}
        units: Dict[str, pedm_types.PedmOrganizationUnit] = {
            self._enterprise_unit.ou_uid: self._enterprise_unit
        }
        if self._enterprise_unit.ou_uid in unit_tree:
            self._enterprise_unit.children_ou.update(unit_tree[self._enterprise_unit.ou_uid])

        for entity in self.storage.entities.get_all_entities():
            if entity.entity_type == pedm_constants.POLICY_DB_TYPE:
                policy_uid = entity.entity_uid
                try:
                    if policy_uid not in policy_keys:
                        raise ValueError(f'Missing policy "{policy_uid}" key')
                    policy_key = policy_keys[policy_uid]
                    if policy_key:
                        data = crypto.decrypt_aes_v2(entity.data, policy_key)
                        json_data = json.loads(data)
                        if policy_uid in policy_agents:
                            pa = frozenset((x for x in policy_agents[policy_uid] if x in agents))
                        else:
                            pa = frozenset()
                        policies[policy_uid] = pedm_types.PedmPolicy(
                            policy_uid=policy_uid, policy_key=policy_key, data=json_data, agents=pa)
                    else:
                        raise Exception('missing encryption key')
                except Exception as e:
                    logger.debug('Policy "%s" decryption error: %s', policy_uid, e)
            elif entity.entity_type == pedm_constants.UNIT_DB_TYPE:
                try:
                    ou_uid = entity.entity_uid
                    data = crypto.decrypt_aes_v2(entity.data, tree_key)
                    json_data = json.loads(data)
                    if ou_uid in unit_tree:
                        us = frozenset(unit_tree[ou_uid])
                    else:
                        us = frozenset()
                    if ou_uid in unit_agents:
                        up = frozenset(unit_agents[ou_uid])
                    else:
                        up = frozenset()
                    units[ou_uid] = pedm_types.PedmOrganizationUnit(
                        ou_uid=ou_uid, parent_ou_uid='', data=json_data, children_ou=us, agents=up)
                except Exception as e:
                    logger.debug('Unit "%s" decryption error: %s', entity.entity_uid, e)
            else:
                logger.debug('Entity "%s" type "%d" is not supported', entity.entity_uid, entity.entity_type)
        o: Any
        for parent, children in unit_tree.items():
            for ou_uid in children:
                if ou_uid in units:
                    units[ou_uid].parent_ou_uid = parent

        self._units.clear()
        self._units.put_entities((_PedmOrganizationUnit(**attrs.asdict(o)) for o in units.values()))

        self._policies.clear()
        self._policies.put_entities((_PedmPolicy(**attrs.asdict(o)) for o in policies.values()))

    def _load_agents(self) -> None:
        public_keys = {x.agent_uid: x.public_key for x in self._agents.get_all_entities() if x.public_key}
        self._agents.clear()

        pam_rs = self.loader.keeper_auth.execute_auth_rest(
            'pam/get_controllers', None, response_type=pam_pb2.PAMControllersResponse)

        def parse_agents() -> Iterator[pedm_types.PedmAgent]:
            assert pam_rs
            for c in pam_rs.controllers:
                if not c.applicationUid:
                    continue
                if c.appClientType != enterprise_pb2.AppClientType.DISCOVERY_AND_ROTATION_CONTROLLER:
                    continue
                hm = hmac.new(utils.base64_url_decode(pedm_constants.AGENT_KEY), digestmod=hashlib.sha256)
                hm.update(c.controllerUid)
                agent_hash = hm.digest()
                egress_uid = utils.base64_url_encode(agent_hash[:16])
                ingress_uid = utils.base64_url_encode(agent_hash[16:])
                yield pedm_types.PedmAgent(
                    agent_uid=utils.base64_url_encode(c.controllerUid), agent_name=c.controllerName, created=c.created,
                    egress_uid=egress_uid, ingress_uid=ingress_uid, is_initialized=c.isInitialized)

        agents: Dict[str, pedm_types.PedmAgent] = {x.agent_uid: x for x in parse_agents()}
        if len(agents) > 0:
            need_keys = [x.agent_uid for x in agents.values() if x.is_initialized is True and x.agent_uid not in public_keys]
            if len(need_keys) > 0:
                pk_rq = APIRequest_pb2.GetKsmPublicKeysRequest()
                pk_rq.controllerUids.extend((utils.base64_url_decode(x) for x in need_keys))
                pk_rs = self.loader.keeper_auth.execute_auth_rest(
                    'vault/get_ksm_public_keys', pk_rq, response_type=APIRequest_pb2.GetKsmPublicKeysResponse)
                assert pk_rs
                for krs in pk_rs.keyResponses:
                    agent_uid = utils.base64_url_encode(krs.controllerUid)
                    public_keys[agent_uid] = krs.publicKey

            for agent_uid, agent in agents.items():
                if agent_uid in public_keys:
                    agent.public_key = public_keys[agent_uid]
            o: Any
            self._agents.put_entities((_PedmAgent(**attrs.asdict(o)) for o in agents.values()))

    def sync_down(self, *, reload: bool = False) -> None:
        if reload is True:
            self.storage.reset()
            self._populate_agents = True

        if self._populate_agents is True:
            self._load_agents()
            self._populate_agents = False

        logger = utils.get_logger()
        agent_streams: Dict[str, str] = {}
        for agent in self._agents.get_all_entities():
            if not agent.public_key:
                continue
            agent_streams[agent.egress_uid] = agent.agent_uid

        device_uid = utils.generate_uid()
        entities_to_put: Dict[str, pedm_storage.PedmEntityData] = {}
        entities_to_delete: Set[str] = set()
        links_to_put: Dict[Tuple[str, str], pedm_storage.PedmLinkData] = {}
        links_to_delete: Set[Tuple[str, str]] = set()

        streams = [self.enterprise_uid]
        streams.extend(agent_streams.keys())
        for stream_uid in streams:
            settings = self.storage.settings.get_entity(stream_uid)
            if settings is None:
                settings = pedm_storage.PedmStreamSettings(stream_uid=stream_uid, sync_point=0)

            sync_point = settings.sync_point
            sync_rq = dag.DagSyncRequest(
                graph_id=pedm_constants.PEDM_GRAPH_ID, stream_id=stream_uid, device_id=device_uid)

            done = False
            while not done:
                sync_rq.sync_point = sync_point
                rs = self.loader.keeper_auth.keeper_endpoint.execute_router(
                    'sync', session_token=self.loader.keeper_auth.auth_context.session_token, request=sync_rq.to_dict())
                assert rs is not None

                done = not (rs.get('hasMore') is True)
                sp = rs.get('syncPoint')
                if isinstance(sp, int):
                    sync_point = sp

                data = rs.get('data')
                if isinstance(data, list):
                    for ed in data:
                        try:
                            edge = dag.DagEdge.parse(ed)
                            if edge is None:
                                continue
                            if not edge.content:
                                continue

                            json_data = json.loads(edge.content)
                            if not isinstance(json_data, dict):
                                raise ValueError(f'Invalid edge content')

                            if edge.parentRef is None:  # entity
                                if stream_uid != self.enterprise_uid:
                                    continue
                                if 'entity_type' not in json_data:
                                    raise ValueError('Edge content does not contain entity_type')
                                entity_type = json_data.get('entity_type')
                                if entity_type not in (pedm_constants.UNIT_DB_TYPE, pedm_constants.POLICY_DB_TYPE):
                                    raise ValueError(f'Invalid entity type: {entity_type}')
                                entity_uid = edge.ref.value

                                if edge.type == dag.EdgeType.DATA:
                                    if 'encrypted_data' not in json_data:
                                        raise ValueError('Edge content does not contain encrypted_data')
                                    content = utils.base64_url_decode(json_data['encrypted_data'])
                                    entity = pedm_storage.PedmEntityData(
                                        entity_uid=entity_uid, entity_type=entity_type, data=content)
                                    entities_to_put[entity_uid] = entity
                                    if entity_uid in entities_to_delete:
                                        entities_to_delete.remove(entity_uid)
                                elif edge.type == dag.EdgeType.DELETION:
                                    entities_to_delete.add(entity_uid)
                                    if entity_uid in entities_to_put:
                                        del entities_to_put[entity_uid]
                                else:
                                    raise ValueError(f'Invalid entity "{entity_type}" action type: {edge.type}')
                            else:  # link
                                if 'link_type' not in json_data:
                                    raise ValueError('Edge content does not contain link_type')
                                link_type = json_data.get('link_type')
                                if link_type not in (pedm_constants.AGENT_UNIT_DB_TYPE, pedm_constants.POLICY_KEY_DB_TYPE,
                                                     pedm_constants.UNIT_PARENT_DB_TYPE):
                                    raise ValueError(f'Invalid link type: {link_type}')
                                entity_uid = edge.ref.value
                                parent_uid = edge.parentRef.value

                                key = (entity_uid, parent_uid)
                                if edge.type in (dag.EdgeType.LINK, dag.EdgeType.KEY):
                                    content = None
                                    if edge.type == dag.EdgeType.KEY:
                                        if 'encrypted_key' not in json_data:
                                            raise ValueError('Edge content does not contain encrypted_key')
                                        content = utils.base64_url_decode(json_data['encrypted_key'])
                                    link = pedm_storage.PedmLinkData(
                                        entity_uid=entity_uid, parent_uid=parent_uid, link_type=link_type, data=content or b'')
                                    links_to_put[key] = link
                                    if key in links_to_delete:
                                        links_to_delete.remove(key)
                                elif edge.type == dag.EdgeType.DELETION:
                                    if key in links_to_put:
                                        del links_to_put[key]
                                    links_to_delete.add(key)
                                else:
                                    raise ValueError(f'Invalid link {link_type} edge action: {edge.type}')
                        except Exception as e:
                            logger.warning(e)

            if settings.sync_point != sync_point:
                settings.sync_point = sync_point
                self.storage.settings.put_entities([settings])

        if len(entities_to_put) > 0:
            self.storage.entities.put_entities(entities_to_put.values())
        if len(entities_to_delete) > 0:
            self.storage.entities.delete_uids(entities_to_delete)
        if len(links_to_put) > 0:
            self.storage.links.put_links(links_to_put.values())
        if len(links_to_delete) > 0:
            self.storage.links.delete_links(links_to_delete)

        self.build_data()

    def delete_ou(self, ou_uid: str) -> Iterable[dag.DagEdge]:
        existing_ou = self.units.get_entity(ou_uid)
        if existing_ou is not None:
            parent_ref = dag.Ref(type=pedm_constants.UNIT_REF_TYPE, value=ou_uid)
            ent_ref = dag.Ref(type=pedm_constants.ENTERPRISE_REF_TYPE, value=self.enterprise_uid)
            # relink children and policies to enterprise

            content = json.dumps({'link_type': pedm_constants.UNIT_PARENT_DB_TYPE}).encode('utf-8')
            if existing_ou.children_ou:
                for child_uid in existing_ou.children_ou:
                    ref = dag.Ref(type=pedm_constants.UNIT_REF_TYPE, value=child_uid)
                    yield dag.DagEdge(type=dag.EdgeType.DELETION, ref=ref, parentRef=parent_ref, content=content)
                    yield dag.DagEdge(type=dag.EdgeType.LINK, ref=ref, parentRef=ent_ref, content=content)

            content = json.dumps({'link_type': pedm_constants.AGENT_UNIT_DB_TYPE}).encode('utf-8')
            if existing_ou.agents:
                for agent_uid in existing_ou.agents:
                    ref = dag.Ref(type=pedm_constants.AGENT_REF_TYPE, value=agent_uid)
                    yield dag.DagEdge(type=dag.EdgeType.DELETION, ref=ref, parentRef=parent_ref, content=content)
                    yield dag.DagEdge(type=dag.EdgeType.LINK, ref=ref, parentRef=ent_ref, content=content)

            content = json.dumps({'entity_type': pedm_constants.UNIT_DB_TYPE}).encode('utf-8')
            yield dag.DagEdge(type=dag.EdgeType.DELETION, ref=parent_ref, content=content)


    def put_ou(self, ou: pedm_types.PedmOrganizationUnit) -> Iterable[dag.DagEdge]:
        unit_uid = ou.ou_uid or utils.generate_uid()
        parent_unit_uid = ou.parent_ou_uid or self.enterprise_uid

        add_parent_link = True
        add_ou_data = True
        ref = dag.Ref(type=pedm_constants.UNIT_REF_TYPE, value=unit_uid)
        existing_ou = self.units.get_entity(unit_uid)
        if existing_ou is not None:
            if existing_ou.parent_ou_uid == parent_unit_uid:
                add_parent_link = False
            else:
                if existing_ou.parent_ou_uid and existing_ou.parent_ou_uid != self.enterprise_uid:
                    parent_ref = dag.Ref(type=pedm_constants.UNIT_REF_TYPE, value=existing_ou.parent_ou_uid)
                else:
                    parent_ref = dag.Ref(type=pedm_constants.ENTERPRISE_REF_TYPE, value=self.enterprise_uid)
                content = json.dumps({'link_type': pedm_constants.UNIT_PARENT_DB_TYPE}).encode('utf-8')
                yield dag.DagEdge(type=dag.EdgeType.DELETION, ref=ref, parentRef=parent_ref, content=content)
            if ou.data:
                add_ou_data = existing_ou.data != ou.data
            else:
                add_ou_data = False
        else:
            if not ou.data:
                raise ValueError(f'Organization Unit "{ou.ou_uid}" does not have data')

        if add_ou_data and isinstance(ou.data, dict):
            data = json.dumps(ou.data).encode('utf-8')
            data = crypto.encrypt_aes_v2(data, self.loader.enterprise_data.enterprise_info.tree_key)
            dict_content = {
                'entity_type': pedm_constants.UNIT_DB_TYPE,
                'encrypted_data': utils.base64_url_encode(data),
            }
            yield dag.DagEdge(type=dag.EdgeType.DATA, ref=ref,  content=json.dumps(dict_content).encode())

        if add_parent_link:
            parent_ref_type = pedm_constants.UNIT_REF_TYPE if parent_unit_uid != self.enterprise_uid else pedm_constants.ENTERPRISE_REF_TYPE
            parent_ref = dag.Ref(type=parent_ref_type, value=parent_unit_uid)
            content = json.dumps({'link_type': pedm_constants.UNIT_PARENT_DB_TYPE}).encode()
            yield dag.DagEdge(type=dag.EdgeType.LINK, ref=ref, parentRef=parent_ref, content=content)

    def put_policy(self, policy: pedm_types.PedmPolicy) -> Iterable[dag.DagEdge]:
        tree_key = self.loader.enterprise_data.enterprise_info.tree_key

        ref = dag.Ref(type=pedm_constants.POLICY_REF_TYPE, value=policy.policy_uid)
        ent_ref = dag.Ref(type=pedm_constants.ENTERPRISE_REF_TYPE, value=self.enterprise_uid)
        existing_policy = self._policies.get_entity(policy.policy_uid)
        update_policy = True
        policy_key: bytes
        if existing_policy is None:
            if not policy.policy_uid:
                policy.policy_uid = utils.generate_uid()
            policy_key = utils.generate_aes_key()
            encrypted_key = crypto.encrypt_aes_v2(policy_key, tree_key)
            content = {
                'link_type': pedm_constants.POLICY_KEY_DB_TYPE,
                'encrypted_key': utils.base64_url_encode(encrypted_key),
            }
            yield dag.DagEdge(type=dag.EdgeType.KEY, ref=ref, parentRef=ent_ref, content=json.dumps(content).encode())
        else:
            policy_key = existing_policy.policy_key
            if policy.data is None:
                update_policy = False
                policy.data = existing_policy.data
            else:
                update_policy = policy.data != existing_policy.data
        if update_policy:
            data = json.dumps(policy.data).encode('utf-8')
            data = crypto.encrypt_aes_v2(data, policy_key)
            content = {
                'entity_type': pedm_constants.POLICY_DB_TYPE,
                'encrypted_data': utils.base64_url_encode(data),
            }
            yield dag.DagEdge(type=dag.EdgeType.DATA, ref=ref, content=json.dumps(content).encode())

    def delete_policy(self, policy_uid: str) -> Iterable[dag.DagEdge]:
        existing_policy = self._policies.get_entity(policy_uid)
        if existing_policy is not None:
            ref = dag.Ref(type=pedm_constants.POLICY_REF_TYPE, value=policy_uid)
            # unlink from agents
            for agent_uid in existing_policy.agent_uids:
                agent_ref = dag.Ref(type=pedm_constants.AGENT_REF_TYPE, value=agent_uid)
                content = json.dumps({'link_type': pedm_constants.POLICY_KEY_DB_TYPE}).encode()
                yield dag.DagEdge(type=dag.EdgeType.DELETION, ref=ref, parentRef=agent_ref, content=content)

            dict_content = {'entity_type': pedm_constants.POLICY_DB_TYPE}
            yield dag.DagEdge(type=dag.EdgeType.DELETION, ref=ref, content=json.dumps(dict_content).encode())

            ent_ref = dag.Ref(type=pedm_constants.ENTERPRISE_REF_TYPE, value=self.enterprise_uid)
            dict_content = {'link_type': pedm_constants.POLICY_KEY_DB_TYPE}
            yield dag.DagEdge(type=dag.EdgeType.DELETION, ref=ref, parentRef=ent_ref, content=json.dumps(dict_content).encode())

    def add_policy_to_agent(self, policy_uid: str, agent_uid: str) -> Iterable[dag.DagEdge]:
        existing_policy = self._policies.get_entity(policy_uid)
        existing_agent = self._agents.get_entity(agent_uid)
        if existing_policy is not None and existing_agent is not None and existing_agent.public_key:
            agent_endpoint_uid = existing_agent.egress_uid
            ref = dag.Ref(type=pedm_constants.POLICY_REF_TYPE, value=policy_uid)
            parent_ref = dag.Ref(type=pedm_constants.AGENT_STREAM_REF_TYPE, value=agent_endpoint_uid)
            public_key = crypto.load_ec_public_key(existing_agent.public_key)
            encrypted_key = crypto.encrypt_ec(existing_policy.policy_key, public_key)
            content = {
                'link_type': pedm_constants.POLICY_KEY_DB_TYPE,
                'encrypted_key': utils.base64_url_encode(encrypted_key),
            }
            yield dag.DagEdge(type=dag.EdgeType.KEY, ref=ref, parentRef=parent_ref, content=json.dumps(content).encode())

    def remove_policy_from_agent(self, policy_uid: str, agent_uid: str) -> Iterable[dag.DagEdge]:
        existing_policy = self._policies.get_entity(policy_uid)
        existing_agent = self._agents.get_entity(agent_uid)
        if existing_policy is not None and existing_agent is not None:
            ref = dag.Ref(type=pedm_constants.POLICY_REF_TYPE, value=policy_uid)
            agent_endpoint_uid = existing_agent.egress_uid
            parent_ref = dag.Ref(type=pedm_constants.AGENT_STREAM_REF_TYPE, value=agent_endpoint_uid)
            content = {'link_type': pedm_constants.POLICY_KEY_DB_TYPE}
            yield dag.DagEdge(type=dag.EdgeType.DELETION, ref=ref, parentRef=parent_ref, content=json.dumps(content).encode())

    def add_agent_to_unit(self, agent_uid: str, ou_uid: str) -> Iterable[dag.DagEdge]:
        existing_agent = self._agents.get_entity(agent_uid)
        existing_unit = self._units.get_entity(ou_uid) if ou_uid else self.enterprise_unit
        if existing_unit is not None and existing_agent is not None:
            if existing_unit.agents is not None and existing_agent.agent_uid not in existing_unit.agents:
                ref = dag.Ref(type=pedm_constants.AGENT_REF_TYPE, value=agent_uid)
                if utils.base64_url_decode(existing_unit.ou_uid) == self.enterprise_uid:
                    parent_ref = dag.Ref(type=pedm_constants.ENTERPRISE_REF_TYPE, value=self.enterprise_uid)
                else:
                    parent_ref = dag.Ref(type=pedm_constants.UNIT_REF_TYPE, value=ou_uid)
                content = {'link_type': pedm_constants.AGENT_UNIT_DB_TYPE}
                yield dag.DagEdge(type=dag.EdgeType.LINK, ref=ref, parentRef=parent_ref, content=json.dumps(content).encode())

    def remove_agent_from_unit(self, agent_uid: str, ou_uid: str) -> Iterable[dag.DagEdge]:
        existing_agent = self._agents.get_entity(agent_uid)
        existing_unit = self._units.get_entity(ou_uid) if ou_uid else self.enterprise_unit
        if existing_unit is not None and existing_agent is not None:
            if existing_unit.agents and existing_agent.agent_uid in existing_unit.agents:
                ref = dag.Ref(type=pedm_constants.AGENT_REF_TYPE, value=ou_uid)
                if utils.base64_url_decode(existing_unit.ou_uid) == self.enterprise_uid:
                    parent_ref = dag.Ref(type=pedm_constants.ENTERPRISE_REF_TYPE, value=self.enterprise_uid)
                else:
                    parent_ref = dag.Ref(type=pedm_constants.UNIT_REF_TYPE, value=ou_uid)
                content = {'link_type': pedm_constants.AGENT_UNIT_DB_TYPE}
                yield dag.DagEdge(type=dag.EdgeType.DELETION, ref=ref, parentRef=parent_ref, content=json.dumps(content).encode())

    def post_edges(self, edges: List[dag.DagEdge]) -> None:
        origin = dag.Ref(type=dag.RefType.DEVICE, value=self.device_uid)
        actor = dag.DagActor(type=dag.ActorType.USER, actor_id=self.enterprise_uid)
        add_rq = dag.DagAddRequest(graph_id=pedm_constants.PEDM_GRAPH_ID, origin=origin, data_list=edges, actor=actor)
        auth = self.loader.keeper_auth
        auth.execute_router('add_data', request=add_rq.to_dict())
        self.sync_down()
