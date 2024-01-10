from typing import Optional, Set, List, Dict, Iterable, Tuple

from . import enterprise_types
from .enterprise_data import EnterpriseData
from .. import utils, crypto
from ..authentication import keeper_auth
from ..proto import enterprise_pb2


class EnterpriseLoader(enterprise_types.IEnterpriseLoader):
    def __init__(self, auth: keeper_auth.KeeperAuth, storage: Optional[enterprise_types.IEnterpriseStorage]=None):
        super().__init__()
        self._keeper_auth = auth
        self._storage = storage
        self._enterprise_data: Optional[EnterpriseData] = None
        self._continuation_token: Optional[bytes] = None

    @property
    def storage(self) -> enterprise_types.IEnterpriseStorage:
        assert self._storage is not None
        return self._storage

    @property
    def enterprise_data(self) -> enterprise_types.IEnterpriseData:
        assert self._enterprise_data is not None
        return self._enterprise_data

    @property
    def keeper_auth(self) -> keeper_auth.KeeperAuth:
        return self._keeper_auth

    def load_role_keys(self, role_keys: Dict[int, Optional[bytes]]) -> None:
        role_ids = {role_id for role_id, key in role_keys.items() if not key}
        if len(role_ids) > 0:
            tree_key = self.enterprise_data.enterprise_info.tree_key
            rq_rk = enterprise_pb2.GetEnterpriseDataKeysRequest()
            rq_rk.roleId.extend(role_ids)
            rs_rk = self.keeper_auth.execute_auth_rest(
                'enterprise/get_enterprise_data_keys', rq_rk,
                response_type=enterprise_pb2.GetEnterpriseDataKeysResponse)
            assert rs_rk is not None
            if len(rs_rk.reEncryptedRoleKey) > 0:
                for rk2 in rs_rk.reEncryptedRoleKey:
                    try:
                        role_keys[rk2.role_id] = crypto.decrypt_aes_v2(rk2.encryptedRoleKey, tree_key)
                    except Exception as e:
                        utils.get_logger().debug('Role key decryption error: %s', e)

            if len(rs_rk.roleKey) > 0:
                auth_context = self._keeper_auth.auth_context
                for rk1 in rs_rk.roleKey:
                    try:
                        enc_data = utils.base64_url_decode(rk1.encryptedKey)
                        if rk1.keyType == enterprise_pb2.KT_ENCRYPTED_BY_DATA_KEY:
                            role_keys[rk1.roleId] = crypto.decrypt_aes_v1(enc_data, auth_context.data_key)
                        elif rk1.keyType == enterprise_pb2.KT_ENCRYPTED_BY_PUBLIC_KEY:
                            assert auth_context.rsa_private_key is not None
                            role_keys[rk1.roleId] = crypto.decrypt_rsa(enc_data, auth_context.rsa_private_key)
                        if rk1.keyType == enterprise_pb2.KT_ENCRYPTED_BY_DATA_KEY_GCM:
                            role_keys[rk1.roleId] = crypto.decrypt_aes_v2(enc_data, auth_context.data_key)
                        elif rk1.keyType == enterprise_pb2.KT_ENCRYPTED_BY_PUBLIC_KEY_ECC:
                            assert auth_context.ec_private_key is not None
                            role_keys[rk1.roleId] = crypto.decrypt_ec(enc_data, auth_context.ec_private_key)
                    except Exception as e:
                        utils.get_logger().debug('Role key decryption error: %s', e)

    def load(self) -> Set[int]:
        logger = utils.get_logger()

        if self._enterprise_data is None:
            self._enterprise_data = EnterpriseData()
            enterprise_info = self._enterprise_data.enterprise_info()

            auth_context = self._keeper_auth.auth_context

            rq_keys = enterprise_pb2.GetEnterpriseDataKeysRequest()
            rs_keys = self._keeper_auth.execute_auth_rest(
                'enterprise/get_enterprise_data_keys', rq_keys,
                response_type=enterprise_pb2.GetEnterpriseDataKeysResponse)
            assert rs_keys is not None
            encrypted_tree_key = utils.base64_url_decode(rs_keys.treeKey.treeKey)
            if rs_keys.treeKey.keyTypeId == enterprise_pb2.ENCRYPTED_BY_DATA_KEY:
                enterprise_info._tree_key = crypto.decrypt_aes_v1(encrypted_tree_key, auth_context.data_key)
            elif rs_keys.treeKey.keyTypeId == enterprise_pb2.ENCRYPTED_BY_PUBLIC_KEY:
                if len(encrypted_tree_key) == 60:
                    enterprise_info._tree_key = crypto.decrypt_aes_v2(encrypted_tree_key, auth_context.data_key)
                else:
                    assert auth_context.rsa_private_key is not None
                    enterprise_info._tree_key = crypto.decrypt_rsa(encrypted_tree_key, auth_context.rsa_private_key)
            elif rs_keys.treeKey.keyTypeId == enterprise_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
                enterprise_info._tree_key = crypto.decrypt_aes_v2(encrypted_tree_key, auth_context.data_key)
            elif rs_keys.treeKey.keyTypeId == enterprise_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
                assert auth_context.ec_private_key is not None
                enterprise_info._tree_key = crypto.decrypt_ec(encrypted_tree_key, auth_context.ec_private_key)

            if rs_keys.enterpriseKeys.rsaEncryptedPrivateKey:
                decrypted_key = crypto.decrypt_aes_v2(rs_keys.enterpriseKeys.rsaEncryptedPrivateKey, enterprise_info.tree_key)
                enterprise_info._rsa_key = crypto.load_rsa_private_key(decrypted_key)
            else:
                rsa_private, rsa_public = crypto.generate_rsa_key()
                rsa_private_key = crypto.unload_rsa_private_key(rsa_private)
                rsa_encrypted_private_key = crypto.encrypt_aes_v2(rsa_private_key, enterprise_info.tree_key)
                rsa_public_key = crypto.unload_rsa_public_key(rsa_public)
                rq = enterprise_pb2.EnterpriseKeyPairRequest()
                rq.enterprisePublicKey = rsa_public_key
                rq.encryptedEnterprisePrivateKey = rsa_encrypted_private_key
                rq.keyType = enterprise_pb2.RSA
                self._keeper_auth.execute_auth_rest('enterprise/set_enterprise_key_pair', rq)
                enterprise_info._rsa_key = rsa_private

            if rs_keys.enterpriseKeys.eccEncryptedPrivateKey:
                encrypted_key = rs_keys.enterpriseKeys.rsaEncryptedPrivateKey
                decrypted_key = crypto.decrypt_aes_v2(encrypted_key, enterprise_info.tree_key)
                enterprise_info._ec_key = crypto.load_ec_private_key(decrypted_key)
            else:
                ec_private, ec_public = crypto.generate_ec_key()
                ec_private_key = crypto.unload_ec_private_key(ec_private)
                ec_encrypted_private_key = crypto.encrypt_aes_v2(ec_private_key, enterprise_info.tree_key)
                ec_public_key = crypto.unload_ec_public_key(ec_public)
                rq = enterprise_pb2.EnterpriseKeyPairRequest()
                rq.enterprisePublicKey = ec_public_key
                rq.encryptedEnterprisePrivateKey = ec_encrypted_private_key
                rq.keyType = enterprise_pb2.ECC
                self._keeper_auth.execute_auth_rest('enterprise/set_enterprise_key_pair', rq)
                enterprise_info._ec_key = ec_private

        enterprise_data = self._enterprise_data
        tree_key = enterprise_data.enterprise_info().tree_key
        if self._continuation_token is None:
            if self._storage is not None:
                settings = self._storage.settings.load()
                if settings is not None:
                    self._continuation_token = settings.continuation_token
                for entity in self._storage.entity_data.get_all_links():
                    plugin = self._enterprise_data.get_plugin(entity.type)
                    if plugin is not None:
                        plugin.store_data(entity.data, tree_key)

        stored_entities: Set[int] = set()
        deleted_entities: Set[int] = set()

        enterprise_info = self._enterprise_data.enterprise_info()
        add_to_storage: List[enterprise_types.EnterpriseEntityData] = []
        remove_from_storage: List[Tuple[int, str]] = []
        while True:
            rq_data = enterprise_pb2.EnterpriseDataRequest()
            continuation_token = self._continuation_token
            if continuation_token:
                rq_data.continuationToken = continuation_token
            rs_data = self._keeper_auth.execute_auth_rest('enterprise/get_enterprise_data_for_user',
                                                          rq_data, response_type=enterprise_pb2.EnterpriseDataResponse)
            assert rs_data is not None
            if rs_data.cacheStatus == enterprise_pb2.CLEAR:
                if self._storage is not None:
                    self._storage.clear()

                for entity_id in self._enterprise_data.get_supported_entities():
                    plugin = self._enterprise_data.get_plugin(entity_id)
                    if plugin is not None:
                        plugin.clear()

            if not enterprise_info.enterprise_name:
                enterprise_info._enterprise_name = rs_data.generalData.enterpriseName
                enterprise_info._is_distributor = rs_data.generalData.distributor

            for ed in rs_data.data:
                plugin = self._enterprise_data.get_plugin(ed.entity)
                if plugin is None:
                    continue
                if ed.delete:
                    deleted_entities.add(ed.entity)
                else:
                    stored_entities.add(ed.entity)

                for edd in ed.data:
                    storage_key: Optional[str]
                    if ed.delete:
                        storage_key = plugin.delete_data(edd)
                    else:
                        storage_key = plugin.store_data(edd, tree_key)
                    if storage_key:
                        if ed.delete:
                            remove_from_storage.append((ed.entity, storage_key))
                        else:
                            add_to_storage.append(enterprise_types.EnterpriseEntityData(type=ed.entity, key=storage_key, data=edd))

            self._continuation_token = rs_data.continuationToken
            if not rs_data.hasMore:
                break

        if self._storage is not None:
            settings = self._storage.settings.load()
            if settings is None:
                settings = enterprise_types.EnterpriseSettings()
            settings.continuation_token = self._continuation_token
            self._storage.settings.store(settings)

        if enterprise_data.root_node is None:
            n: enterprise_types.Node
            for n in enterprise_data.nodes().get_all_entities():
                if n.parent_id is None or n.parent_id == 0:
                    enterprise_data._root_node = n
                    break

        if enterprise_pb2.TEAMS in deleted_entities:
            remove_from_storage.extend(self._delete_team_links())
        if enterprise_pb2.ROLES in deleted_entities:
            remove_from_storage.extend(self._delete_role_links())
        if enterprise_pb2.MANAGED_NODES in deleted_entities:
            remove_from_storage.extend(self._delete_managed_node_links())
        if enterprise_pb2.USERS in deleted_entities:
            remove_from_storage.extend(self._delete_user_links())

        if self._storage is not None:
            if len(remove_from_storage) > 0:
                self._storage.entity_data.delete_links(remove_from_storage)
            if len(add_to_storage) > 0:
                self._storage.entity_data.put_links(add_to_storage)

        return stored_entities.union(deleted_entities)

    def _delete_team_links(self) -> Iterable[Tuple[int, str]]:
        assert self._enterprise_data is not None
        team_uids = {x.team_uid for x in self._enterprise_data.teams().get_all_entities()}

        team_users = [x for x in self._enterprise_data.team_users().get_all_links() if x.team_uid not in team_uids]
        tup = self._enterprise_data.team_user_plugin
        for tul in team_users:
            tup.delete_entity(tul)
            yield enterprise_pb2.TEAM_USERS, tup.storage_key(tul)

        role_teams = [x for x in self._enterprise_data.role_teams().get_all_links() if x.team_uid not in team_uids]
        rtp = self._enterprise_data.role_team_plugin
        for rtl in role_teams:
            rtp.delete_entity(rtl)
            yield enterprise_pb2.TEAM_USERS, rtp.storage_key(rtl)

    def _delete_role_links(self) -> Iterable[Tuple[int, str]]:
        assert self._enterprise_data is not None
        role_ids = {x.role_id for x in self._enterprise_data.roles().get_all_entities()}

        role_enfs = [x for x in self._enterprise_data.role_enforcements().get_all_links() if x.role_id not in role_ids]
        rep = self._enterprise_data.role_enforcement_plugin
        for rel in role_enfs:
            rep.delete_entity(rel)
            yield enterprise_pb2.ROLE_ENFORCEMENTS, rep.storage_key(rel)

        role_teams = [x for x in self._enterprise_data.role_teams().get_all_links() if x.role_id not in role_ids]
        rtp = self._enterprise_data.role_team_plugin
        for rtl in role_teams:
            rtp.delete_entity(rtl)
            yield enterprise_pb2.ROLE_TEAMS, rtp.storage_key(rtl)

        role_users = [x for x in self._enterprise_data.role_users().get_all_links() if x.role_id not in role_ids]
        rup = self._enterprise_data.role_user_plugin
        for rul in role_users:
            rup.delete_entity(rul)
            yield enterprise_pb2.ROLE_USERS, rup.storage_key(rul)

        role_privs = [x for x in self._enterprise_data.role_privileges().get_all_links() if x.role_id not in role_ids]
        rpp = self._enterprise_data.role_privilege_plugin
        for rpl in role_privs:
            rpp.delete_all_privileges(rpl.role_id, rpl.managed_node_id)
            for key in rpp.storage_keys(rpl):
                yield enterprise_pb2.ROLE_PRIVILEGES, key

    def _delete_managed_node_links(self) -> Iterable[Tuple[int, str]]:
        assert self._enterprise_data is not None
        mn_ids = {(x.role_id, x.managed_node_id) for x in self._enterprise_data.managed_nodes().get_all_links()}
        role_privs = [x for x in self._enterprise_data.role_privileges().get_all_links() if
                      (x.role_id, x.managed_node_id) not in mn_ids]
        rpp = self._enterprise_data.role_privilege_plugin
        for rpl in role_privs:
            rpp.delete_all_privileges(rpl.role_id, rpl.managed_node_id)
            for key in rpp.storage_keys(rpl):
                yield enterprise_pb2.ROLE_PRIVILEGES, key

    def _delete_user_links(self) -> Iterable[Tuple[int, str]]:
        assert self._enterprise_data is not None
        user_ids = {x.enterprise_user_id for x in self._enterprise_data.users().get_all_entities()}

        role_users = [x for x in self._enterprise_data.role_users().get_all_links() if x.enterprise_user_id not in user_ids]
        rup = self._enterprise_data.role_user_plugin
        for rul in role_users:
            rup.delete_entity(rul)
            yield enterprise_pb2.ROLE_USERS, rup.storage_key(rul)

        team_users = [x for x in self._enterprise_data.team_users().get_all_links() if x.enterprise_user_id not in user_ids]
        tup = self._enterprise_data.team_user_plugin
        for tul in team_users:
            tup.delete_entity(tul)
            yield enterprise_pb2.TEAM_USERS, tup.storage_key(tul)

        user_aliases = [x for x in self._enterprise_data.user_aliases().get_all_links() if x.enterprise_user_id not in user_ids]
        uap = self._enterprise_data.user_alias_plugin
        for ual in user_aliases:
            uap.delete_entity(ual)
            yield enterprise_pb2.USER_ALIASES, uap.storage_key(ual)

        # TODO queued_team_users
