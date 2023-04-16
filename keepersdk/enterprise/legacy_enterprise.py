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

import abc
import json
from typing import Dict, List, Tuple, Set, Any, Type, Optional

from google.protobuf.message import Message

from .enterprise_types import EnterpriseData, EnterpriseInfo
from .. import crypto, utils
from ..proto import enterprise_pb2


def _to_key_type(key_type):  # type: (enterprise_pb2.EncryptedKeyType) -> str
    if key_type == enterprise_pb2.KT_ENCRYPTED_BY_DATA_KEY:
        return 'encrypted_by_data_key'
    if key_type == enterprise_pb2.KT_ENCRYPTED_BY_PUBLIC_KEY:
        return 'encrypted_by_public_key'
    if key_type == enterprise_pb2.KT_ENCRYPTED_BY_DATA_KEY_GCM:
        return 'encrypted_by_data_key_gcm'
    if key_type == enterprise_pb2.KT_ENCRYPTED_BY_PUBLIC_KEY_ECC:
        return 'encrypted_by_public_key_ecc'
    return 'no_key'


class LegacyEnterpriseData(EnterpriseData):
    def __init__(self):   # type: () -> None
        self._enterprise = EnterpriseInfo()
        self._data_types = {
            enterprise_pb2.NODES: _EnterpriseNodeEntity(self._enterprise),
            enterprise_pb2.USERS: _EnterpriseUserEntity(self._enterprise),
            enterprise_pb2.TEAMS: _EnterpriseTeamEntity(self._enterprise),
            enterprise_pb2.ROLES: _EnterpriseRoleEntity(self._enterprise),
            enterprise_pb2.LICENSES: _EnterpriseLicenseEntity(self._enterprise),
            enterprise_pb2.QUEUED_TEAMS: _EnterpriseQueuedTeamEntity(self._enterprise),
            enterprise_pb2.SCIMS: _EnterpriseScimEntity(self._enterprise),
            enterprise_pb2.SSO_SERVICES: _EnterpriseSsoServiceEntity(self._enterprise),
            enterprise_pb2.BRIDGES: _EnterpriseBridgeEntity(self._enterprise),
            enterprise_pb2.EMAIL_PROVISION: _EnterpriseEmailProvisionEntity(self._enterprise),
            enterprise_pb2.TEAM_USERS: _EnterpriseTeamUserEntity(self._enterprise),
            enterprise_pb2.QUEUED_TEAM_USERS: _EnterpriseQueuedTeamUserEntity(self._enterprise),
            enterprise_pb2.ROLE_USERS: _EnterpriseRoleUserEntity(self._enterprise),
            enterprise_pb2.ROLE_TEAMS: _EnterpriseRoleTeamEntity(self._enterprise),
            enterprise_pb2.MANAGED_NODES: _EnterpriseManagedNodeEntity(self._enterprise),
            enterprise_pb2.ROLE_PRIVILEGES: _EnterpriseRolePrivilegeEntity(self._enterprise),
            enterprise_pb2.ROLE_ENFORCEMENTS: _EnterpriseRoleEnforcements(self._enterprise),
            enterprise_pb2.MANAGED_COMPANIES: _EnterpriseManagedCompanyEntity(self._enterprise),
            enterprise_pb2.DEVICES_REQUEST_FOR_ADMIN_APPROVAL: _EnterpriseAdminApprovalRequestEntity(self._enterprise),
            enterprise_pb2.USER_ALIASES: _EnterpriseUserAliasEntity(self._enterprise),
        }   # type: Dict[int, _EnterpriseBaseDataType]
        self._role_keys = {}    # type: Dict[int, Dict]
        self._role_keys2 = {}   # type: Dict[int, Dict]

        teams = self._data_types[enterprise_pb2.TEAMS]
        if isinstance(teams, _EnterpriseDataEntity):
            teams.register_link('team_uid', self._data_types[enterprise_pb2.TEAM_USERS])
            teams.register_link('team_uid', self._data_types[enterprise_pb2.ROLE_TEAMS])

        users = self._data_types[enterprise_pb2.USERS]
        if isinstance(users, _EnterpriseDataEntity):
            users.register_link('enterprise_user_id', self._data_types[enterprise_pb2.TEAM_USERS])
            users.register_link('enterprise_user_id', self._data_types[enterprise_pb2.ROLE_USERS])

        roles = self._data_types[enterprise_pb2.ROLES]
        if isinstance(roles, _EnterpriseDataEntity):
            roles.register_link('role_id', self._data_types[enterprise_pb2.ROLE_TEAMS])
            roles.register_link('role_id', self._data_types[enterprise_pb2.ROLE_USERS])
            roles.register_link('role_id', self._data_types[enterprise_pb2.MANAGED_NODES])
            roles.register_link('role_id', self._data_types[enterprise_pb2.ROLE_ENFORCEMENTS])

    @property
    def enterprise_info(self):
        return self._enterprise

    def put_entity(self, entity_type, data):
        if entity_type in self._data_types:
            e_type = self._data_types[entity_type]
            e_type.store(data, False)

    def delete_entity(self, entity_type, data):
        if entity_type in self._data_types:
            e_type = self._data_types[entity_type]
            e_type.store(data, False)

    def clear(self):
        for e_type in self._data_types.values():
            e_type.clear()
        self._role_keys.clear()
        self._role_keys2.clear()

    def put_role_key(self, role_id, key_type, encrypted_key):
        self._role_keys[role_id] = {
            'role_id': role_id,
            'key_type': _to_key_type(key_type),
            'encrypted_key': utils.base64_url_encode(encrypted_key)
        }

    def put_role_key2(self, role_id, encrypted_key):
        self._role_keys2[role_id] = {
            'role_id': role_id,
            'encrypted_key': utils.base64_url_encode(encrypted_key)
        }

    def get_missing_role_keys(self):   # type: () -> List[int]
        role_ids = set()   # type: Set[int]
        managed_nodes = self._data_types[enterprise_pb2.MANAGED_NODES]
        if isinstance(managed_nodes, _Entities):
            role_ids.update((x['role_id'] for x in managed_nodes.entities.values() if 'role_id' in x))
        role_ids.difference_update(self._role_keys.keys())
        role_ids.difference_update(self._role_keys2.keys())
        return list(role_ids)

    def synchronize(self, enterprise_data, entities=None):
        # type: (Dict, Optional[Set[enterprise_pb2.EnterpriseDataEntity]]) -> None
        for data_type, entity in self._data_types.items():
            if isinstance(entities, set):
                if data_type not in entities:
                    continue
            entity_name = entity.get_keeper_entity_name()
            entity_list = enterprise_data.get(entity_name)
            if entity_list is None:
                entity_list = []
                enterprise_data[entity_name] = entity_list
            entity.export(entity_list)
            if len(entity_list) == 0:
                del enterprise_data[entity_name]

        role_keys = enterprise_data.get('role_keys')
        if role_keys or len(self._role_keys) > 0:
            if role_keys is None:
                role_keys = []
                enterprise_data['role_keys'] = role_keys
            role_uids = set(x['role_id'] for x in role_keys)
            role_uids.difference_update(self._role_keys.keys())
            if len(role_uids) != 0:
                role_keys.clear()
                role_keys.extend(self._role_keys.values())
        role_keys2 = enterprise_data.get('role_keys2')
        if role_keys2 or len(self._role_keys2) > 0:
            if role_keys2 is None:
                role_keys2 = []
                enterprise_data['role_keys2'] = role_keys2
            role_uids = set(x['role_id'] for x in role_keys2)
            role_uids.difference_update(self._role_keys2.keys())
            if len(role_uids) != 0:
                role_keys2.clear()
                role_keys2.extend(self._role_keys2.values())


class _EnterpriseBaseDataType(abc.ABC):
    def __init__(self, enterprise):    # type: (EnterpriseInfo) -> None
        self.enterprise = enterprise

    @abc.abstractmethod
    def store(self, data, is_delete):  # type: (bytes, bool) -> None
        pass

    @abc.abstractmethod
    def export(self, entities):  # type: (List) -> None
        pass

    @abc.abstractmethod
    def clear(self):  # type: () -> None
        pass

    @abc.abstractmethod
    def get_entity_type(self):  # type: () -> Type[Message]
        pass

    @abc.abstractmethod
    def get_keeper_entity_name(self):  # type: () -> str
        pass


class _Entities(abc.ABC):
    @property
    @abc.abstractmethod
    def entities(self):  # type:  () -> Dict[str, Dict]
        pass


class _EnterpriseDataEntity(_EnterpriseBaseDataType, _Entities):
    def __init__(self, enterprise):    # type: (EnterpriseInfo) -> None
        super(_EnterpriseDataEntity, self).__init__(enterprise)
        self._entities = {}    # type: Dict[str, Dict]
        self._links = []       # type: List[Tuple[str, _EnterpriseLink]]

    @property
    def entities(self):  # type:  () -> Dict[str, Dict]
        return self._entities

    def store(self, data, is_delete):  # type: (bytes, bool) -> None
        entity_type = self.get_entity_type()
        entity = entity_type()
        entity.ParseFromString(data)
        entity_key = self.get_proto_entity_key(entity)
        if is_delete:
            if entity_key in self._entities:
                del self._entities[entity_key]
                for keeper_entity_id_name, link in self._links:
                    link.cascade_delete(keeper_entity_id_name, entity_key)
        else:
            keeper_entity = self._entities.get(entity_key)
            if not keeper_entity:
                keeper_entity = {}
                self._entities[entity_key] = keeper_entity
            self.to_keeper_entity(entity, keeper_entity)

    def export(self, entities):  # type: (List) -> None
        entities.clear()
        entities.extend(self._entities.values())

    def clear(self):  # type: () -> None
        self._entities.clear()
        for _, link in self._links:
            if isinstance(link, _EnterpriseBaseDataType):
                link.clear()

    @staticmethod
    def fix_data(d):
        idx = d.rfind(b'}')
        if idx < len(d) - 1:
            d = d[:idx+1]
        return d

    @staticmethod
    def _set_or_remove(obj, key, value):  # type: (dict, str, Any) -> None
        if value is not None:
            obj[key] = value
        else:
            if key in obj:
                obj.pop(key)

    def register_link(self, keeper_entity_id_name, parser):  # type: (str, _EnterpriseBaseDataType) -> None
        if isinstance(parser, _EnterpriseLink):
            self._links.append((keeper_entity_id_name, parser))

    @abc.abstractmethod
    def get_keeper_entity_key(self, proto_entity):  # type: (dict) -> str
        pass

    @abc.abstractmethod
    def get_proto_entity_key(self, proto_entity):  # type: (Message) -> str
        pass

    @abc.abstractmethod
    def to_keeper_entity(self, proto_entity, keeper_entity):
        pass


class _EnterpriseLink(_Entities, abc.ABC):
    def cascade_delete(self, keeper_entity_id, value):   # type: (str, Any) -> None
        to_delete = {k for k, v in self.entities.items() if keeper_entity_id in v and v[keeper_entity_id] == value}
        if len(to_delete) > 0:
            for key in to_delete:
                del self.entities[key]


class _EnterpriseNodeEntity(_EnterpriseDataEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.Node, dict) -> None
        self._set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        self._set_or_remove(keeper_entity, 'parent_id', proto_entity.parentId if proto_entity.parentId > 0 else None)
        self._set_or_remove(keeper_entity, 'bridge_id', proto_entity.bridgeId if proto_entity.bridgeId > 0 else None)
        self._set_or_remove(keeper_entity, 'scim_id', proto_entity.scimId if proto_entity.scimId > 0 else None)
        self._set_or_remove(keeper_entity, 'license_id', proto_entity.licenseId if proto_entity.licenseId > 0 else None)
        self._set_or_remove(keeper_entity, 'encrypted_data', proto_entity.encryptedData)
        self._set_or_remove(keeper_entity, 'duo_enabled', True if proto_entity.duoEnabled else None)
        self._set_or_remove(keeper_entity, 'rsa_enabled', True if proto_entity.rsaEnabled else None)
        self._set_or_remove(keeper_entity, 'sso_service_provider_id',
                            proto_entity.ssoServiceProviderId if proto_entity.ssoServiceProviderId > 0 else None)
        self._set_or_remove(keeper_entity, 'restrict_visibility',
                            proto_entity.restrictVisibility if proto_entity.restrictVisibility else None)

        data = {}
        if 'encrypted_data' in keeper_entity:
            try:
                encrypted_data = utils.base64_url_decode(keeper_entity['encrypted_data'])
                data_json = crypto.decrypt_aes_v1(encrypted_data, self.enterprise.tree_key)
                data_json = self.fix_data(data_json)
                data.update(json.loads(data_json.decode('utf-8')))
            except Exception as e:
                utils.get_logger().warning('Decrypt encryption data error: %s', e)
        elif 'parent_id' not in keeper_entity:
            data['displayname'] = self.enterprise.enterprise_name
        keeper_entity['data'] = data

    def get_keeper_entity_key(self, entity):
        return str(entity.get('node_id'))

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.Node)
        return str(entity.nodeId)

    def get_entity_type(self):
        return enterprise_pb2.Node

    def get_keeper_entity_name(self):  # type: () -> str
        return 'nodes'


class _EnterpriseUserEntity(_EnterpriseDataEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.User, dict) -> None
        self._set_or_remove(keeper_entity, 'enterprise_user_id', proto_entity.enterpriseUserId)
        self._set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        self._set_or_remove(keeper_entity, 'username', proto_entity.username)
        self._set_or_remove(keeper_entity, 'encrypted_data', proto_entity.encryptedData)
        self._set_or_remove(keeper_entity, 'key_type', proto_entity.keyType)
        self._set_or_remove(keeper_entity, 'status', proto_entity.status)
        self._set_or_remove(keeper_entity, 'lock', proto_entity.lock)
        self._set_or_remove(keeper_entity, 'user_id', proto_entity.userId)
        self._set_or_remove(keeper_entity, 'account_share_expiration',
                            proto_entity.accountShareExpiration if proto_entity.accountShareExpiration > 0 else None)
        self._set_or_remove(keeper_entity, 'full_name', proto_entity.fullName if proto_entity.fullName else None)
        self._set_or_remove(keeper_entity, 'job_title', proto_entity.jobTitle if proto_entity.jobTitle else None)
        data = {}
        encrypted_data = keeper_entity.get('encrypted_data')
        if encrypted_data:
            if keeper_entity.get('key_type') == 'no_key':
                data['displayname'] = encrypted_data
            else:
                try:
                    data_json = crypto.decrypt_aes_v1(utils.base64_url_decode(encrypted_data), self.enterprise.tree_key)
                    data_json = self.fix_data(data_json)
                    data.update(json.loads(data_json.decode('utf-8')))
                except Exception as e:
                    utils.get_logger().warning('Decrypt User data error: %s', e)
        elif 'full_name' in keeper_entity:
            data['displayname'] = keeper_entity['full_name']
        keeper_entity['data'] = data

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return str(entity.get('enterprise_user_id'))

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.User)
        return str(entity.enterpriseUserId)

    def get_entity_type(self):
        return enterprise_pb2.User

    def get_keeper_entity_name(self):  # type: () -> str
        return 'users'


class _EnterpriseTeamEntity(_EnterpriseDataEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.Team, dict) -> None
        self._set_or_remove(keeper_entity, 'team_uid', utils.base64_url_encode(proto_entity.teamUid))
        self._set_or_remove(keeper_entity, 'name', proto_entity.name)
        self._set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        self._set_or_remove(keeper_entity, 'restrict_edit', proto_entity.restrictEdit)
        self._set_or_remove(keeper_entity, 'restrict_sharing', proto_entity.restrictShare)
        self._set_or_remove(keeper_entity, 'restrict_view', proto_entity.restrictView)
        self._set_or_remove(keeper_entity, 'encrypted_data', proto_entity.encryptedData)
        self._set_or_remove(keeper_entity, 'encrypted_team_key', proto_entity.encryptedTeamKey)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> Any
        return entity.get('team_uid')

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.Team)
        return utils.base64_url_encode(entity.teamUid)

    def get_entity_type(self):
        return enterprise_pb2.Team

    def get_keeper_entity_name(self):  # type: () -> str
        return 'teams'


class _EnterpriseRoleEntity(_EnterpriseDataEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.Role, dict) -> None
        self._set_or_remove(keeper_entity, 'role_id', proto_entity.roleId)
        self._set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        self._set_or_remove(keeper_entity, 'encrypted_data', proto_entity.encryptedData)
        self._set_or_remove(keeper_entity, 'visible_below', proto_entity.visibleBelow)
        self._set_or_remove(keeper_entity, 'new_user_inherit', proto_entity.newUserInherit)
        self._set_or_remove(keeper_entity, 'key_type', proto_entity.keyType)
        self._set_or_remove(keeper_entity, 'role_type', proto_entity.roleType)
        data = {}
        encrypted_data = keeper_entity.get('encrypted_data')
        if encrypted_data:
            try:
                data_json = crypto.decrypt_aes_v1(utils.base64_url_decode(encrypted_data), self.enterprise.tree_key)
                data_json = self.fix_data(data_json)
                data.update(json.loads(data_json.decode('utf-8')))
                if proto_entity.roleType == "pool_manager":
                    data['displayname'] = 'MSP Subscription Manager'
            except Exception as e:
                utils.get_logger().warning('Decrypt encryption data error: %s', e)
        keeper_entity['data'] = data

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return str(entity.get('role_id'))

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.Role)
        return str(entity.roleId)

    def get_entity_type(self):
        return enterprise_pb2.Role

    def get_keeper_entity_name(self):  # type: () -> str
        return 'roles'


class _EnterpriseLicenseEntity(_EnterpriseDataEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.License, dict) -> None
        self._set_or_remove(keeper_entity, 'paid', proto_entity.paid)
        self._set_or_remove(keeper_entity, 'number_of_seats', proto_entity.numberOfSeats)
        self._set_or_remove(keeper_entity, 'expiration', proto_entity.expiration)
        self._set_or_remove(keeper_entity, 'license_key_id',
                            proto_entity.licenseKeyId if proto_entity.licenseKeyId > 0 else None)
        self._set_or_remove(keeper_entity, 'product_type_id',
                            proto_entity.productTypeId if proto_entity.productTypeId > 0 else None)
        self._set_or_remove(keeper_entity, 'name', proto_entity.name)
        self._set_or_remove(keeper_entity, 'enterprise_license_id', proto_entity.enterpriseLicenseId)
        self._set_or_remove(keeper_entity, 'seats_allocated', proto_entity.seatsAllocated)
        self._set_or_remove(keeper_entity, 'seats_pending', proto_entity.seatsPending)
        self._set_or_remove(keeper_entity, 'tier', proto_entity.tier)
        self._set_or_remove(keeper_entity, 'file_plan',
                            proto_entity.filePlanTypeId if proto_entity.filePlanTypeId > 0 else None)
        self._set_or_remove(keeper_entity, 'max_gb',
                            proto_entity.maxBytes // 2**30 if proto_entity.filePlanTypeId > 0 else None)
        self._set_or_remove(keeper_entity, 'storage_expiration',
                            proto_entity.storageExpiration if proto_entity.storageExpiration > 0 else None)
        self._set_or_remove(keeper_entity, 'lic_status', proto_entity.licenseStatus)
        self._set_or_remove(keeper_entity, 'distributor', proto_entity.distributor)

        if proto_entity.mspPool:
            msp_pool = [{
                'product_id': x.productId,
                'seats': x.seats,
                'availableSeats': x.availableSeats,
                'stash': x.stash
            } for x in proto_entity.mspPool]
            self._set_or_remove(keeper_entity, 'msp_pool', msp_pool)

        if proto_entity.managedBy and proto_entity.managedBy.enterpriseId > 0:
            self._set_or_remove(keeper_entity, 'managed_by', {
                'enterprise_id': proto_entity.managedBy.enterpriseId,
                'enterprise_name': proto_entity.managedBy.enterpriseName,
            })

        if proto_entity.addOns:
            self._set_or_remove(keeper_entity, 'add_ons', [{
                'name': x.name,
                'enabled': x.enabled,
                'is_trial': x.isTrial,
                'created': x.created,
                'expiration': x.expiration,
            } for x in proto_entity.addOns])

        if proto_entity.mspPermits.restricted:
            self._set_or_remove(keeper_entity, 'msp_permits', {
                'allow_unlimited_licenses': proto_entity.mspPermits.allowUnlimitedLicenses,
                'allowed_mc_products': [x for x in proto_entity.mspPermits.allowedMcProducts],
                'allowed_add_ons': [x for x in proto_entity.mspPermits.allowedAddOns],
                'max_file_plan_type': proto_entity.mspPermits.maxFilePlanType,
                'mc_defaults': [{
                    'mc_product': x.mcProduct,
                    'add_ons': [a for a in x.addOns],
                    'file_plan_type': x.filePlanType,
                } for x in proto_entity.mspPermits.mcDefaults]
            })

        self._set_or_remove(keeper_entity, 'next_billing_date',
                            proto_entity.nextBillingDate if proto_entity.nextBillingDate > 0 else None)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> Any
        return str(entity.get('enterprise_license_id'))

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.License)
        return str(entity.enterpriseLicenseId)

    def get_entity_type(self):
        return enterprise_pb2.License

    def get_keeper_entity_name(self):  # type: () -> str
        return 'licenses'


class _EnterpriseQueuedTeamEntity(_EnterpriseDataEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.QueuedTeam, dict) -> None
        self._set_or_remove(keeper_entity, 'team_uid', utils.base64_url_encode(proto_entity.teamUid))
        self._set_or_remove(keeper_entity, 'name', proto_entity.name)
        self._set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        self._set_or_remove(keeper_entity, 'encrypted_data', proto_entity.encryptedData)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return entity['team_uid']

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.QueuedTeam)
        return utils.base64_url_encode(entity.teamUid)

    def get_entity_type(self):
        return enterprise_pb2.QueuedTeam

    def get_keeper_entity_name(self):  # type: () -> str
        return 'queued_teams'


class _EnterpriseScimEntity(_EnterpriseDataEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.Scim, dict) -> None
        self._set_or_remove(keeper_entity, 'scim_id', proto_entity.scimId)
        self._set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        self._set_or_remove(keeper_entity, 'status', proto_entity.status)
        self._set_or_remove(keeper_entity, 'last_synced',
                            proto_entity.lastSynced if proto_entity.lastSynced > 0 else None)
        self._set_or_remove(keeper_entity, 'role_prefix', proto_entity.rolePrefix)
        self._set_or_remove(keeper_entity, 'unique_groups', proto_entity.uniqueGroups)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return str(entity.get('scim_id'))

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.Scim)
        return str(entity.scimId)

    def get_entity_type(self):
        return enterprise_pb2.Scim

    def get_keeper_entity_name(self):  # type: () -> str
        return 'scims'


class _EnterpriseSsoServiceEntity(_EnterpriseDataEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.SsoService, dict) -> None
        self._set_or_remove(keeper_entity, 'sso_service_provider_id', proto_entity.ssoServiceProviderId)
        self._set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        self._set_or_remove(keeper_entity, 'name', proto_entity.name)
        self._set_or_remove(keeper_entity, 'sp_url', proto_entity.sp_url)
        self._set_or_remove(keeper_entity, 'invite_new_users', proto_entity.inviteNewUsers)
        self._set_or_remove(keeper_entity, 'active', proto_entity.active)
        self._set_or_remove(keeper_entity, 'is_cloud', proto_entity.isCloud)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return str(entity.get('sso_service_provider_id'))

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.SsoService)
        return str(entity.ssoServiceProviderId)

    def get_entity_type(self):
        return enterprise_pb2.SsoService

    def get_keeper_entity_name(self):  # type: () -> str
        return 'sso_services'


class _EnterpriseBridgeEntity(_EnterpriseDataEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.Bridge, dict) -> None
        self._set_or_remove(keeper_entity, 'bridge_id', proto_entity.bridgeId)
        self._set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        self._set_or_remove(keeper_entity, 'wan_ip_enforcement', proto_entity.wanIpEnforcement)
        self._set_or_remove(keeper_entity, 'lan_ip_enforcement', proto_entity.lanIpEnforcement)
        self._set_or_remove(keeper_entity, 'status', proto_entity.status)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return str(entity.get('bridge_id'))

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.Bridge)
        return str(entity.bridgeId)

    def get_entity_type(self):
        return enterprise_pb2.Bridge

    def get_keeper_entity_name(self):  # type: () -> str
        return 'bridges'


class _EnterpriseEmailProvisionEntity(_EnterpriseDataEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.EmailProvision, dict) -> None
        self._set_or_remove(keeper_entity, 'id', proto_entity.id)
        self._set_or_remove(keeper_entity, 'node_id', proto_entity.nodeId)
        self._set_or_remove(keeper_entity, 'domain', proto_entity.domain)
        self._set_or_remove(keeper_entity, 'method', proto_entity.method)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return str(entity.get('id'))

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.EmailProvision)
        return str(entity.id)

    def get_entity_type(self):
        return enterprise_pb2.EmailProvision

    def get_keeper_entity_name(self):  # type: () -> str
        return 'email_provision'


class _EnterpriseTeamUserEntity(_EnterpriseDataEntity, _EnterpriseLink):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.TeamUser, dict) -> None
        self._set_or_remove(keeper_entity, 'team_uid', utils.base64_url_encode(proto_entity.teamUid))
        self._set_or_remove(keeper_entity, 'enterprise_user_id', proto_entity.enterpriseUserId)
        user_type = 0 if proto_entity.userType == 'USER' else 1 if proto_entity.userType == 'ADMIN' else 2
        self._set_or_remove(keeper_entity, 'user_type', user_type)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return f'{entity.get("team_uid")}:{entity.get("enterprise_user_id")}'

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.TeamUser)
        return f'{utils.base64_url_encode(entity.teamUid)}:{entity.enterpriseUserId}'

    def get_entity_type(self):
        return enterprise_pb2.TeamUser

    def get_keeper_entity_name(self):  # type: () -> str
        return 'team_users'


class _EnterpriseRoleUserEntity(_EnterpriseDataEntity, _EnterpriseLink):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.RoleUser, dict) -> None
        self._set_or_remove(keeper_entity, 'role_id', proto_entity.roleId)
        self._set_or_remove(keeper_entity, 'enterprise_user_id', proto_entity.enterpriseUserId)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return f'{entity.get("role_id")}:{entity.get("enterprise_user_id")}'

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.RoleUser)
        return f'{entity.roleId}:{entity.enterpriseUserId}'

    def get_entity_type(self):
        return enterprise_pb2.RoleUser

    def get_keeper_entity_name(self):  # type: () -> str
        return 'role_users'


class _EnterpriseRoleTeamEntity(_EnterpriseDataEntity, _EnterpriseLink):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.RoleTeam, dict) -> None
        self._set_or_remove(keeper_entity, 'role_id', proto_entity.role_id)
        self._set_or_remove(keeper_entity, 'team_uid', utils.base64_url_encode(proto_entity.teamUid))

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return f'{entity.get("role_id")}:{entity.get("team_uid")}'

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.RoleTeam)
        return f'{entity.role_id}:{utils.base64_url_encode(entity.teamUid)}'

    def get_entity_type(self):
        return enterprise_pb2.RoleTeam

    def get_keeper_entity_name(self):  # type: () -> str
        return 'role_teams'


class _EnterpriseManagedNodeEntity(_EnterpriseDataEntity, _EnterpriseLink):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.ManagedNode, dict) -> None
        self._set_or_remove(keeper_entity, 'role_id', proto_entity.roleId)
        self._set_or_remove(keeper_entity, 'managed_node_id', proto_entity.managedNodeId)
        self._set_or_remove(keeper_entity, 'cascade_node_management', proto_entity.cascadeNodeManagement)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return f'{entity.get("role_id")}:{entity.get("managed_node_id")}'

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.ManagedNode)
        return f'{entity.roleId}:{entity.managedNodeId}'

    def get_entity_type(self):
        return enterprise_pb2.ManagedNode

    def get_keeper_entity_name(self):  # type: () -> str
        return 'managed_nodes'


class _EnterpriseRolePrivilegeEntity(_EnterpriseDataEntity, _EnterpriseLink):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.RolePrivilege, dict) -> None
        self._set_or_remove(keeper_entity, 'role_id', proto_entity.roleId)
        self._set_or_remove(keeper_entity, 'managed_node_id', proto_entity.managedNodeId)
        self._set_or_remove(keeper_entity, 'privilege', proto_entity.privilegeType)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return f'{entity.get("role_id")}:{entity.get("managed_node_id")}:{entity.get("privilege")}'

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.RolePrivilege)
        return f'{entity.roleId}:{entity.managedNodeId}:{entity.privilegeType}'

    def get_entity_type(self):
        return enterprise_pb2.RolePrivilege

    def get_keeper_entity_name(self):  # type: () -> str
        return 'role_privileges'


class _EnterpriseManagedCompanyEntity(_EnterpriseDataEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):  # type: (enterprise_pb2.ManagedCompany, dict) -> None
        self._set_or_remove(keeper_entity, 'mc_enterprise_id', proto_entity.mcEnterpriseId)
        self._set_or_remove(keeper_entity, 'mc_enterprise_name', proto_entity.mcEnterpriseName)
        self._set_or_remove(keeper_entity, 'msp_node_id', proto_entity.mspNodeId)
        self._set_or_remove(keeper_entity, 'number_of_seats', proto_entity.numberOfSeats)
        self._set_or_remove(keeper_entity, 'number_of_users', proto_entity.numberOfUsers)
        self._set_or_remove(keeper_entity, 'product_id', proto_entity.productId)
        self._set_or_remove(keeper_entity, 'paused', proto_entity.isExpired)
        self._set_or_remove(keeper_entity, 'tree_key', proto_entity.treeKey if proto_entity.treeKey else None)
        self._set_or_remove(keeper_entity, 'tree_key_role', proto_entity.tree_key_role)
        self._set_or_remove(keeper_entity, 'file_plan_type', proto_entity.filePlanType)
        self._set_or_remove(keeper_entity, 'add_ons', [{
            'name': x.name,
            'seats': x.seats,
            'enabled': x.enabled,
            'is_trial': x.isTrial,
            'created': x.created,
            'expiration': x.expiration,
            'activation_time': x.activationTime,
            'included_in_product': x.includedInProduct,
        } for x in proto_entity.addOns])

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return str(entity.get('mc_enterprise_id'))

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.ManagedCompany)
        return str(entity.mcEnterpriseId)

    def get_entity_type(self):
        return enterprise_pb2.ManagedCompany

    def get_keeper_entity_name(self):  # type: () -> str
        return 'managed_companies'


class _EnterpriseAdminApprovalRequestEntity(_EnterpriseDataEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):
        # type: (enterprise_pb2.DeviceRequestForAdminApproval, dict) -> None
        self._set_or_remove(keeper_entity, 'enterprise_user_id', proto_entity.enterpriseUserId)
        self._set_or_remove(keeper_entity, 'encrypted_device_token',
                            utils.base64_url_encode(proto_entity.encryptedDeviceToken))
        self._set_or_remove(keeper_entity, 'device_id', proto_entity.deviceId)
        self._set_or_remove(keeper_entity, 'device_public_key', utils.base64_url_encode(proto_entity.devicePublicKey))
        self._set_or_remove(keeper_entity, 'device_name', proto_entity.deviceName)
        self._set_or_remove(keeper_entity, 'client_version', proto_entity.clientVersion)
        self._set_or_remove(keeper_entity, 'device_type', proto_entity.deviceType)
        self._set_or_remove(keeper_entity, 'date', proto_entity.date)
        self._set_or_remove(keeper_entity, 'ip_address', proto_entity.ipAddress)
        self._set_or_remove(keeper_entity, 'location', proto_entity.location)
        self._set_or_remove(keeper_entity, 'email', proto_entity.email)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return f'{entity.get("enterprise_user_id")}:{entity.get("device_id")}'

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.DeviceRequestForAdminApproval)
        return f'{entity.enterpriseUserId}:{entity.deviceId}'

    def get_entity_type(self):
        return enterprise_pb2.DeviceRequestForAdminApproval

    def get_keeper_entity_name(self):  # type: () -> str
        return 'devices_request_for_admin_approval'


class _EnterpriseUserAliasEntity(_EnterpriseDataEntity):
    def to_keeper_entity(self, proto_entity, keeper_entity):    # type: (enterprise_pb2.UserAlias, dict) -> None
        self._set_or_remove(keeper_entity, 'username', proto_entity.username)
        self._set_or_remove(keeper_entity, 'enterprise_user_id', proto_entity.enterpriseUserId)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return entity['username']

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.UserAlias)
        return entity.username

    def get_entity_type(self):
        return enterprise_pb2.UserAlias

    def get_keeper_entity_name(self):  # type: () -> str
        return 'user_aliases'


class _EnterpriseRoleEnforcements(_EnterpriseDataEntity, _EnterpriseLink):
    def to_keeper_entity(self, proto_entity, keeper_entity):    # type: (enterprise_pb2.RoleEnforcement, dict) -> None
        self._set_or_remove(keeper_entity, 'role_id', proto_entity.roleId)
        self._set_or_remove(keeper_entity, 'enforcement_type', proto_entity.enforcementType)
        self._set_or_remove(keeper_entity, 'value', proto_entity.value)

    def get_keeper_entity_key(self, entity):  # type: (dict) -> str
        return f'{entity["role_id"]}:{entity["enforcement_type"]}'

    def get_proto_entity_key(self, entity):
        assert isinstance(entity, enterprise_pb2.RoleEnforcement)
        return f'{entity.roleId}:{entity.enforcementType}'

    def get_entity_type(self):
        return enterprise_pb2.RoleEnforcement

    def get_keeper_entity_name(self):  # type: () -> str
        return 'role_enforcements'

    def export(self, entities):  # type: (List) -> None
        role_enforcements = {}   # type: Dict[int, Dict]
        for entity in self._entities.values():
            role_id = entity['role_id']
            if role_id not in role_enforcements:
                role_enforcements[role_id] = {
                    'role_id': role_id
                }
            if 'enforcements' not in role_enforcements[role_id]:
                role_enforcements[role_id]['enforcements'] = {}
            role_enforcements[role_id]['enforcements'][entity['enforcement_type']] = entity['value']

        entities.clear()
        entities.extend(role_enforcements.values())


class _EnterpriseQueuedTeamUserEntity(_EnterpriseBaseDataType, _EnterpriseLink):
    def __init__(self, enterprise):    # type: (EnterpriseInfo) -> None
        super(_EnterpriseQueuedTeamUserEntity, self).__init__(enterprise)
        self._entities = {}    # type: Dict[str, Dict]

    @property
    def entities(self):  # type:  () -> Dict[str, Dict]
        return self._entities

    def store(self, data, is_delete):  # type: (bytes, bool) -> None
        proto_entity = enterprise_pb2.QueuedTeamUser()
        proto_entity.ParseFromString(data)
        entity_key = utils.base64_url_encode(proto_entity.teamUid)
        keeper_entity = self.entities.get(entity_key)
        if not keeper_entity:
            keeper_entity = {
                'team_uid': entity_key,
                'users': []
            }
            self.entities[entity_key] = keeper_entity

        users = set(keeper_entity['users'])
        if is_delete:
            users.difference_update(proto_entity.users)
        else:
            users.update(proto_entity.users)
        if len(users) == 0:
            del self.entities[entity_key]
        else:
            keeper_entity['users'] = list(users)

    def export(self, entities):  # type: (List) -> None
        entities.clear()
        entities.extend(self.entities.values())

    def clear(self):
        self._entities.clear()

    def get_entity_type(self):
        return enterprise_pb2.QueuedTeamUser

    def get_keeper_entity_name(self):
        return 'queued_team_users'
