#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from typing import Optional, Set

from .enterprise_types import EnterpriseStorage, EnterpriseEntityMap, EnterpriseData
from .. import utils, crypto
from ..login import auth
from ..proto import enterprise_pb2


class EnterpriseLoader:
    def __init__(self, external_data, storage=None):
        # type: (EnterpriseData, Optional[EnterpriseStorage]) -> None
        self._storage = storage if storage else _InMemoryEnterpriseStorage()
        self._external_data = external_data

    def load(self, keeper_auth):  # type: (auth.KeeperAuth) -> None
        enterprise_info = self._external_data.enterprise_info
        if not enterprise_info.tree_key:
            rq = enterprise_pb2.GetEnterpriseDataKeysRequest()
            rs = keeper_auth.execute_auth_rest(
                'enterprise/get_enterprise_data_keys', rq, response_type=enterprise_pb2.GetEnterpriseDataKeysResponse)
            if rs.treeKey:
                encrypted_tree_key = utils.base64_url_decode(rs.treeKey.treeKey)
                if rs.treeKey.keyTypeId == enterprise_pb2.ENCRYPTED_BY_DATA_KEY:
                    enterprise_info._tree_key = \
                        crypto.decrypt_aes_v1(encrypted_tree_key, keeper_auth.auth_context.data_key)
                elif rs.treeKey.keyTypeId == enterprise_pb2.ENCRYPTED_BY_PUBLIC_KEY:
                    if len(encrypted_tree_key) == 60:
                        enterprise_info._tree_key = \
                            crypto.decrypt_aes_v2(encrypted_tree_key, keeper_auth.auth_context.data_key)
                    else:
                        enterprise_info._tree_key = \
                            crypto.decrypt_rsa(encrypted_tree_key, keeper_auth.auth_context.rsa_private_key)

            if rs.enterpriseKeys.rsaEncryptedPrivateKey:
                decrypted_key = \
                    crypto.decrypt_aes_v2(rs.enterpriseKeys.rsaEncryptedPrivateKey, enterprise_info.tree_key)
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
                keeper_auth.execute_auth_rest('enterprise/set_enterprise_key_pair', rq)
                enterprise_info._rsa_key = rsa_private

            if rs.enterpriseKeys.eccEncryptedPrivateKey:
                encrypted_key = rs.enterpriseKeys.rsaEncryptedPrivateKey
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
                keeper_auth.execute_auth_rest('enterprise/set_enterprise_key_pair', rq)
                enterprise_info._ec_key = ec_private

            for entity_type, data in self._storage.get_all():
                if entity_type in EnterpriseEntityMap:
                    self._external_data.put_entity(entity_type, data)

        entities = set()    # type: Set[enterprise_pb2.EnterpriseDataEntity]
        while True:
            rq = enterprise_pb2.EnterpriseDataRequest()
            continuation_token = self._storage.get_continuation_token()
            if continuation_token:
                rq.continuationToken = continuation_token
            rs = keeper_auth.execute_auth_rest(
                'enterprise/get_enterprise_data_for_user', rq, response_type=enterprise_pb2.EnterpriseDataResponse)

            if rs.cacheStatus == enterprise_pb2.CLEAR:
                self._storage.clear()
                self._external_data.clear()

            if not enterprise_info.enterprise_name and rs.generalData:
                enterprise_info._enterprise_name = rs.generalData.enterpriseName
                if rs.generalData.distributor:
                    enterprise_info._is_distributor = True

            for ed in rs.data:
                if ed.entity in EnterpriseEntityMap:
                    entities.add(ed.entity)
                    for data in ed.data:
                        if ed.delete:
                            self._storage.delete_entity(ed.entity, data)
                            self._external_data.delete_entity(ed.entity, data)
                        else:
                            self._storage.put_entity(ed.entity, data)
                            self._external_data.put_entity(ed.entity, data)

            self._storage.set_continuation_token(rs.continuationToken)
            if not rs.hasMore:
                break

        self._storage.flush()
        self._external_data.populate(entities)


class _InMemoryEnterpriseStorage(EnterpriseStorage):
    def __init__(self):
        super().__init__()
        self._continuation_token = b''

    def get_continuation_token(self):
        return self._continuation_token

    def set_continuation_token(self, token):
        self._continuation_token = token

    def clear(self):
        pass

    def flush(self):
        pass

    def put_entity(self, entity_type, data):
        pass

    def delete_entity(self, entity_type, data):
        pass

    def get_all(self):
        return iter(())
