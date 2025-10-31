import abc
import json
from typing import Generic, Dict, Optional, Tuple, Iterable, Any, List, Iterator, Type

from . import enterprise_types
from .. import utils, crypto
from ..proto import enterprise_pb2
from ..storage.storage_types import T, K, KS, KO, IEntity, ILink

def to_storage_key(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return value.to_bytes(8, byteorder='big').hex()
    raise ValueError(f'Unsupported key type: {value}')


def get_storage_key(*comps: Any) -> str:
    return '|'.join((to_storage_key(x) for x in comps))

class _IEnterpriseEntity(Generic[T, K], IEntity[T, K], enterprise_types.IEnterprisePlugin[T], abc.ABC):
    def __init__(self) -> None:
        super().__init__()
        self._data: Optional[Dict[K, T]] = None

    @abc.abstractmethod
    def get_entity_key(self, entity: T) -> K:
        pass

    def storage_key(self, entity: T) -> str:
        return get_storage_key(self.get_entity_key(entity))

    def put_entity(self, entity: T) -> None:
        if self._data is None:
            self._data = {}
        key = self.get_entity_key(entity)
        self._data[key] = entity

    def delete_entity(self, entity: T) -> None:
        if self._data is not None:
            key = self.get_entity_key(entity)
            if key in self._data:
                del self._data[key]

    def clear(self) -> None:
        self._data = None

    def get_all_entities(self) -> Iterable[T]:
        if self._data:
            for _, v in self._data.items():
                yield v

    def get_entity(self, key: K) -> Optional[T]:
        if self._data:
            return self._data.get(key)


class _IEnterpriseLink(Generic[T, KS, KO], ILink[T, KS, KO], enterprise_types.IEnterprisePlugin[T], abc.ABC):
    def __init__(self) -> None:
        super().__init__()
        self._data: Optional[Dict[Tuple[KS, KO], T]] = None

    def get_link(self, subject_id: KS, object_id: KO) -> Optional[T]:
        if self._data is not None:
            return self._data.get((subject_id, object_id))

    def get_links_by_subject(self, subject_id: KS) -> Iterable[T]:
        if self._data is not None:
            for k, v in self._data.items():
                if k[0] == subject_id:
                    yield v

    def get_links_by_object(self, object_id: KO) -> Iterable[T]:
        if self._data is not None:
            for k, v in self._data.items():
                if k[1] == object_id:
                    yield v

    def get_all_links(self) -> Iterable[T]:
        if self._data is not None:
            for v in self._data.values():
                yield v

    @abc.abstractmethod
    def get_subject_key(self, entity: T) -> KS:
        pass

    @abc.abstractmethod
    def get_object_key(self, entity: T) -> KO:
        pass

    def storage_key(self, entity: T) -> str:
        return get_storage_key(self.get_subject_key(entity), self.get_object_key(entity))

    def put_entity(self, entity: T) -> None:
        if self._data is None:
            self._data = {}

        key = (self.get_subject_key(entity), self.get_object_key(entity))
        self._data[key] = entity

    def delete_entity(self, entity: T) -> None:
        if self._data is not None:
            key = (self.get_subject_key(entity), self.get_object_key(entity))
            if key in self._data:
                del self._data[key]

    def clear(self) -> None:
        self._data = None


def _decrypt_encrypted_data(data: str, key_type: str, tree_key: bytes) -> Dict[str, Any]:
    ed = utils.base64_url_decode(data)
    if key_type == 'encrypted_by_data_key_gcm':
        ed = crypto.decrypt_aes_v2(ed, tree_key)
    else:
        ed = crypto.decrypt_aes_v1(ed, tree_key)
    return json.loads(ed.decode())


class NodeEntity(_IEnterpriseEntity[enterprise_types.Node, int]):
    def get_entity_key(self, entity: enterprise_types.Node) -> int:
        return entity.node_id

    def decrypt_entity(self, entity: enterprise_types.Node, key: bytes) -> None:
        if entity.encrypted_data:
            try:
                j = _decrypt_encrypted_data(entity.encrypted_data, 'encrypted_by_data_key', key)
                entity.name = j.get('displayname') or ''
            except Exception as e:
                utils.get_logger().debug('error decrypting EncryptedData: %s', e)

    def convert_entity(self, data) -> enterprise_types.Node:
        proto_entity = enterprise_pb2.Node()
        proto_entity.ParseFromString(data)
        entity = enterprise_types.Node(node_id=proto_entity.nodeId, parent_id=proto_entity.parentId,
                      duo_enabled=proto_entity.duoEnabled, rsa_enabled=proto_entity.rsaEnabled,
                      restrict_visibility=proto_entity.restrictVisibility, encrypted_data=proto_entity.encryptedData)
        if proto_entity.bridgeId > 0:
            entity.bridge_id = proto_entity.bridgeId
        if proto_entity.scimId > 0:
            entity.scim_id = proto_entity.scimId
        if proto_entity.licenseId > 0:
            entity.license_id = proto_entity.licenseId
        if len(proto_entity.ssoServiceProviderIds) > 0:
            entity.sso_service_provided_ids = list(proto_entity.ssoServiceProviderIds)
        return entity

    @classmethod
    def frozen_entity_type(cls) -> Type[enterprise_types.Node]:
        return enterprise_types.INode


class RoleEntity(_IEnterpriseEntity[enterprise_types.Role, int]):
    def __init__(self):
        super().__init__()

    def get_entity_key(self, entity: enterprise_types.Role) -> int:
        return entity.role_id

    def decrypt_entity(self, entity: enterprise_types.Role, key: bytes) -> None:
        if entity.encrypted_data:
            if entity.key_type == 'no_key':
                entity.name = entity.encrypted_data
            else:
                try:
                    j = _decrypt_encrypted_data(entity.encrypted_data, entity.key_type, key)
                    entity.name = j.get('displayname') or ''
                except Exception as e:
                    utils.get_logger().debug('error decrypting EncryptedData: %s', e)

    def convert_entity(self, data) -> enterprise_types.Role:
        proto_entity = enterprise_pb2.Role()
        proto_entity.ParseFromString(data)

        role = enterprise_types.Role(role_id=proto_entity.roleId, node_id=proto_entity.nodeId, role_type=proto_entity.roleType,
                 visible_below=proto_entity.visibleBelow, new_user_inherit=proto_entity.newUserInherit,
                 key_type=proto_entity.keyType, encrypted_data=proto_entity.encryptedData)
        return role

    @classmethod
    def frozen_entity_type(cls) -> Type[enterprise_types.Role]:
        return enterprise_types.IRole


class UserEntity(_IEnterpriseEntity[enterprise_types.User, int]):
    def get_entity_key(self, entity: enterprise_types.User) -> int:
        return entity.enterprise_user_id

    def decrypt_entity(self, entity: enterprise_types.User, key: bytes) -> None:
        if entity.encrypted_data:
            if entity.key_type == 'no_key':
                entity.full_name = entity.encrypted_data
            else:
                try:
                    j = _decrypt_encrypted_data(entity.encrypted_data, entity.key_type, key)
                    entity.full_name = j.get('displayname') or ''
                except Exception as e:
                    utils.get_logger().debug('error decrypting EncryptedData: %s', e)

    def convert_entity(self, data) -> enterprise_types.User:
        proto_entity = enterprise_pb2.User()
        proto_entity.ParseFromString(data)
        user = enterprise_types.User(enterprise_user_id=proto_entity.enterpriseUserId, username=proto_entity.username,
                 node_id=proto_entity.nodeId, full_name=proto_entity.fullName, job_title=proto_entity.jobTitle,
                 status=proto_entity.status, lock=proto_entity.lock, user_id=proto_entity.userId,
                 account_share_expiration=proto_entity.accountShareExpiration, tfa_enabled=proto_entity.tfaEnabled,
                 transfer_acceptance_status=proto_entity.transferAcceptanceStatus,
                 key_type=proto_entity.keyType, encrypted_data=proto_entity.encryptedData)
        return user


class TeamEntity(_IEnterpriseEntity[enterprise_types.Team, str]):
    def get_entity_key(self, entity: enterprise_types.Team) -> str:
        return entity.team_uid

    def convert_entity(self, data) -> enterprise_types.Team:
        proto_entity = enterprise_pb2.Team()
        proto_entity.ParseFromString(data)
        team_uid = utils.base64_url_encode(proto_entity.teamUid)
        return enterprise_types.Team(team_uid=team_uid, name=proto_entity.name, node_id=proto_entity.nodeId, restrict_edit=proto_entity.restrictEdit,
                 restrict_share=proto_entity.restrictShare, restrict_view=proto_entity.restrictView, encrypted_data=proto_entity.encryptedData,
                 encrypted_team_key=utils.base64_url_decode(proto_entity.encryptedTeamKey))


class QueuedTeamEntity(_IEnterpriseEntity[enterprise_types.QueuedTeam, str]):
    def get_entity_key(self, entity: enterprise_types.QueuedTeam) -> str:
        return entity.team_uid

    def convert_entity(self, data) -> enterprise_types.QueuedTeam:
        proto_entity = enterprise_pb2.QueuedTeam()
        proto_entity.ParseFromString(data)
        team_uid = utils.base64_url_encode(proto_entity.teamUid)
        return enterprise_types.QueuedTeam(team_uid=team_uid, name=proto_entity.name, node_id=proto_entity.nodeId, encrypted_data=proto_entity.encryptedData)

    @classmethod
    def frozen_entity_type(cls) -> Optional[Type[enterprise_types.QueuedTeam]]:
        return enterprise_types.IQueuedTeam


class TeamUserLink(_IEnterpriseLink[enterprise_types.TeamUser, str, int]):
    def get_subject_key(self, entity: enterprise_types.TeamUser) -> str:
        return entity.team_uid

    def get_object_key(self, entity: enterprise_types.TeamUser) -> int:
        return entity.enterprise_user_id

    def convert_entity(self, data) -> enterprise_types.TeamUser:
        proto_entity = enterprise_pb2.TeamUser()
        proto_entity.ParseFromString(data)
        tu = enterprise_types.TeamUser(team_uid=utils.base64_url_encode(proto_entity.teamUid),
                            enterprise_user_id=proto_entity.enterpriseUserId, user_type=proto_entity.userType)
        return tu


class RoleUserLink(_IEnterpriseLink[enterprise_types.RoleUser, int, int]):
    def get_subject_key(self, entity: enterprise_types.RoleUser) -> int:
        return entity.role_id

    def get_object_key(self, entity: enterprise_types.RoleUser) -> int:
        return entity.enterprise_user_id

    def convert_entity(self, data) -> enterprise_types.RoleUser:
        proto_entity = enterprise_pb2.RoleUser()
        proto_entity.ParseFromString(data)
        rul = enterprise_types.RoleUser(role_id=proto_entity.roleId, enterprise_user_id=proto_entity.enterpriseUserId)
        return rul


class RolePrivilegeLink(ILink[enterprise_types.RolePrivileges, int, int], enterprise_types.IEnterpriseDataPlugin):
    def __init__(self) -> None:
        super().__init__()
        self._data: Optional[Dict[Tuple[int, int], enterprise_types.RolePrivileges]] = None

    @staticmethod
    def storage_keys(entity: enterprise_types.RolePrivileges) -> Iterator[str]:
        for privilege in entity.to_set():
            yield get_storage_key(entity.role_id, entity.managed_node_id, privilege)

    def _store_value(self, data: bytes, value: bool) -> str:
        proto_entity = enterprise_pb2.RolePrivilege()
        proto_entity.ParseFromString(data)
        key = (proto_entity.roleId, proto_entity.managedNodeId)
        if self._data is None:
            self._data = {}

        rp: enterprise_types.RolePrivileges
        if key not in self._data:
            rp = enterprise_types.RolePrivileges(role_id=proto_entity.roleId, managed_node_id=proto_entity.managedNodeId)
            self._data[key] = rp
        else:
            rp = self._data[key]
        rp.set_by_name(proto_entity.privilegeType, value)
        return get_storage_key(proto_entity.roleId, proto_entity.managedNodeId, proto_entity.privilegeType)

    def store_data(self, data: bytes, key: bytes) -> Tuple[str, bytes]:
        return self._store_value(data, True), data

    def delete_data(self, data: bytes) -> Tuple[str, bytes]:
        return self._store_value(data, False), b''

    def delete_all_privileges(self, role_id: int, managed_node_id: int) -> None:
        if self._data is not None:
            if role_id in self._data:
                del self._data[(role_id, managed_node_id)]

    def clear(self) -> None:
        self._data = None

    def get_link(self, subject_id: int, object_id: int) -> Optional[enterprise_types.RolePrivileges]:
        if self._data is not None:
            return self._data.get((subject_id, object_id))

    def get_links_by_subject(self, subject_id: int) -> Iterable[enterprise_types.RolePrivileges]:
        if self._data is not None:
            for k, v in self._data.items():
                if k[0] == subject_id:
                    yield v

    def get_links_by_object(self, object_id: int) -> Iterable[enterprise_types.RolePrivileges]:
        if self._data is not None:
            for k, v in self._data.items():
                if k[1] == object_id:
                    yield v

    def get_all_links(self) -> Iterable[enterprise_types.RolePrivileges]:
        if self._data is not None:
            for v in self._data.values():
                yield v


class RoleEnforcementLink(_IEnterpriseLink[enterprise_types.RoleEnforcement, int, str]):
    def get_subject_key(self, entity: enterprise_types.RoleEnforcement) -> int:
        return entity.role_id

    def get_object_key(self, entity: enterprise_types.RoleEnforcement) -> str:
        return entity.enforcement_type

    def convert_entity(self, data) -> enterprise_types.RoleEnforcement:
        proto_entity = enterprise_pb2.RoleEnforcement()
        proto_entity.ParseFromString(data)
        rel = enterprise_types.RoleEnforcement(
            role_id=proto_entity.roleId, enforcement_type=proto_entity.enforcementType.lower(), value=proto_entity.value)
        return rel


class RoleTeamLink(_IEnterpriseLink[enterprise_types.RoleTeam, int, str]):
    def get_subject_key(self, entity: enterprise_types.RoleTeam) -> int:
        return entity.role_id

    def get_object_key(self, entity: enterprise_types.RoleTeam) -> str:
        return entity.team_uid

    def convert_entity(self, data) -> enterprise_types.RoleTeam:
        proto_entity = enterprise_pb2.RoleTeam()
        proto_entity.ParseFromString(data)
        rt = enterprise_types.RoleTeam(role_id=proto_entity.role_id, team_uid=utils.base64_url_encode(proto_entity.teamUid))
        return rt


class LicenseEntity(_IEnterpriseEntity[enterprise_types.License, int]):
    def get_entity_key(self, entity: enterprise_types.License) -> int:
        return entity.enterprise_license_id

    def convert_entity(self, data) -> enterprise_types.License:
        proto_entity = enterprise_pb2.License()
        proto_entity.ParseFromString(data)

        managed_by: Optional[enterprise_types.MspContact] = None
        if proto_entity.managedBy.enterpriseId > 0:
            managed_by = enterprise_types.MspContact(enterprise_id=proto_entity.managedBy.enterpriseId,
                                                     enterprise_name=proto_entity.managedBy.enterpriseName)

        msp_permits: Optional[enterprise_types.MspPermits] = None
        if proto_entity.mspPermits.restricted:
            mc_defaults: Optional[List[enterprise_types.McDefault]] = None
            if len(proto_entity.mspPermits.mcDefaults) > 0:
                mc_defaults = []
                for mc_default in proto_entity.mspPermits.mcDefaults:
                    add_ons: Optional[List[str]] = None
                    if len(mc_default.addOns) > 0:
                        add_ons = list(mc_default.addOns)
                    mc_defaults.append(enterprise_types.McDefault(
                        mc_product=mc_default.mcProduct, file_plan_type=mc_default.filePlanType, max_licenses=mc_default.maxLicenses,
                        add_ons=add_ons, fixed_max_licenses=mc_default.fixedMaxLicenses))
            allowed_mc_products: Optional[List[str]] = None
            if len(proto_entity.mspPermits.allowedMcProducts) > 0:
                allowed_mc_products = list(proto_entity.mspPermits.allowedMcProducts)
            allowed_add_ons: Optional[List[str]] = None
            if len(proto_entity.mspPermits.allowedAddOns) > 0:
                allowed_add_ons = list(proto_entity.mspPermits.allowedAddOns)
            msp_permits = enterprise_types.MspPermits(
                restricted=proto_entity.mspPermits.restricted, max_file_plan_type=proto_entity.mspPermits.maxFilePlanType,
                allow_unlimited_licenses=proto_entity.mspPermits.allowUnlimitedLicenses, allowed_mc_products=allowed_mc_products,
                allowed_add_ons=allowed_add_ons, mc_defaults=mc_defaults)

        license_add_on: Optional[List[enterprise_types.LicenseAddOn]] = None
        if len(proto_entity.addOns) > 0:
            license_add_on = []
            for add_on in proto_entity.addOns:
                license_add_on.append(enterprise_types.LicenseAddOn(
                    name=add_on.name, enabled=add_on.enabled, included_in_product=add_on.includedInProduct, is_trial=add_on.isTrial,
                    seats=add_on.seats, api_call_count=add_on.apiCallCount, created=add_on.created,
                    activation_time=add_on.activationTime, expiration=add_on.expiration))

        return enterprise_types.License(
            enterprise_license_id=proto_entity.enterpriseLicenseId, license_key_id=proto_entity.licenseKeyId,
            product_type_id=proto_entity.productTypeId, file_plan_id=proto_entity.filePlanTypeId, name=proto_entity.name,
            number_of_seats=proto_entity.numberOfSeats, seats_allocated=proto_entity.seatsAllocated, seats_pending=proto_entity.seatsPending,
            add_ons=license_add_on, license_status=proto_entity.licenseStatus, next_billing_date=proto_entity.nextBillingDate,
            expiration=proto_entity.expiration, storage_expiration=proto_entity.storageExpiration,
            distributor=proto_entity.distributor, msp_permits=msp_permits, managed_by=managed_by)


class ManagedNodeLink(_IEnterpriseLink[enterprise_types.ManagedNode, int, int]):
    def get_subject_key(self, entity: enterprise_types.ManagedNode) -> int:
        return entity.role_id

    def get_object_key(self, entity: enterprise_types.ManagedNode) -> int:
        return entity.managed_node_id

    def convert_entity(self, data) -> enterprise_types.ManagedNode:
        proto_entity = enterprise_pb2.ManagedNode()
        proto_entity.ParseFromString(data)
        mn = enterprise_types.ManagedNode(role_id=proto_entity.roleId, managed_node_id=proto_entity.managedNodeId,
                                         cascade_node_management=proto_entity.cascadeNodeManagement)
        return mn


class ManagedCompanyEntity(_IEnterpriseEntity[enterprise_types.ManagedCompany, int]):
    def get_entity_key(self, entity: enterprise_types.ManagedCompany) -> int:
        return entity.mc_enterprise_id

    def convert_entity(self, data) -> enterprise_types.ManagedCompany:
        proto_entity = enterprise_pb2.ManagedCompany()
        proto_entity.ParseFromString(data)

        license_add_on: Optional[List[enterprise_types.LicenseAddOn]] = None
        if len(proto_entity.addOns) > 0:
            license_add_on = []
            for add_on in proto_entity.addOns:
                license_add_on.append(enterprise_types.LicenseAddOn(
                    name=add_on.name, enabled=add_on.enabled, included_in_product=add_on.includedInProduct, is_trial=add_on.isTrial,
                    seats=add_on.seats, api_call_count=add_on.apiCallCount, created=add_on.created,
                    activation_time=add_on.activationTime, expiration=add_on.expiration))

        return enterprise_types.ManagedCompany(
            mc_enterprise_id=proto_entity.mcEnterpriseId, mc_enterprise_name=proto_entity.mcEnterpriseName,
            msp_node_id=proto_entity.mspNodeId, number_of_seats=proto_entity.numberOfSeats, number_of_users=proto_entity.numberOfUsers,
            product_id=proto_entity.productId, is_expired=proto_entity.isExpired, tree_key=proto_entity.treeKey,
            tree_key_role=proto_entity.tree_key_role, file_plan_type=proto_entity.filePlanType, add_ons=license_add_on)


class DeviceApprovalRequestEntity(_IEnterpriseEntity[enterprise_types.DeviceApprovalRequest, str]):
    
    def get_entity_key(self, entity: enterprise_types.DeviceApprovalRequest) -> str:
        return f'{entity.enterprise_user_id}:{entity.device_id}'
    
    def convert_entity(self, data) -> enterprise_types.DeviceApprovalRequest:
        proto_entity = enterprise_pb2.DeviceRequestForAdminApproval()
        proto_entity.ParseFromString(data)
        
        return enterprise_types.DeviceApprovalRequest(
            enterprise_user_id=proto_entity.enterpriseUserId,
            device_id=proto_entity.deviceId,
            encrypted_device_token=utils.base64_url_encode(proto_entity.encryptedDeviceToken),
            device_public_key=utils.base64_url_encode(proto_entity.devicePublicKey),
            device_name=proto_entity.deviceName,
            client_version=proto_entity.clientVersion,
            device_type=proto_entity.deviceType,
            date=proto_entity.date,
            ip_address=proto_entity.ipAddress,
            location=proto_entity.location,
            email=proto_entity.email,
            account_uid=proto_entity.accountUid
        )

    @classmethod
    def frozen_entity_type(cls) -> Type[enterprise_types.DeviceApprovalRequest]:
        return enterprise_types.IDeviceApprovalRequest


class QueuedTeamUserLink(enterprise_types.ILink[enterprise_types.QueuedTeamUser, str, int], enterprise_types.IEnterpriseDataPlugin):
    def __init__(self) -> None:
        super().__init__()
        self._data: Optional[Dict[Tuple[str, int], enterprise_types.QueuedTeamUser]] = None

    def _store_value(self, data: bytes, is_store: bool) -> str:
        proto_entity = enterprise_pb2.QueuedTeamUser()
        proto_entity.ParseFromString(data)
        if self._data is None:
            self._data = {}
        team_uid = utils.base64_url_encode(proto_entity.teamUid)
        for user_id in proto_entity.users:
            qtu = enterprise_types.QueuedTeamUser(team_uid=team_uid, enterprise_user_id=user_id)
            key = (qtu.team_uid, qtu.enterprise_user_id)
            if is_store:
                self._data[key] = qtu
            else:
                if key in self._data:
                    del self._data[key]

        return team_uid

    def store_data(self, data: bytes, key: bytes) -> Tuple[str, bytes]:
        entity_key = self._store_value(data, True)
        return entity_key, data

    def delete_data(self, data):
        return self._store_value(data, False), data

    def clear(self):
        self._data = None

    def get_link(self, subject_id, object_id):
        if self._data is not None:
            return self._data.get((subject_id, object_id))

    def get_links_by_subject(self, subject_id):
        if self._data is not None:
            for k, v in self._data.items():
                if k[0] == subject_id:
                    yield v

    def get_links_by_object(self, object_id):
        if self._data is not None:
            for k, v in self._data.items():
                if k[1] == object_id:
                    yield v

    def get_all_links(self):
        if self._data is not None:
            for v in self._data.values():
                yield v


class UserAliasLink(_IEnterpriseLink[enterprise_types.UserAlias, int, str]):
    def get_subject_key(self, entity: enterprise_types.UserAlias) -> int:
        return entity.enterprise_user_id

    def get_object_key(self, entity: enterprise_types.UserAlias) -> str:
        return entity.username

    def convert_entity(self, data):
        proto_entity = enterprise_pb2.UserAlias()
        proto_entity.ParseFromString(data)
        return enterprise_types.UserAlias(enterprise_user_id=proto_entity.enterpriseUserId, username=proto_entity.username)


class BridgeEntity(_IEnterpriseEntity[enterprise_types.Bridge, int]):
    def get_entity_key(self, entity):
        return entity.bridge_id

    def convert_entity(self, data):
        proto_entity = enterprise_pb2.Bridge()
        proto_entity.ParseFromString(data)
        return enterprise_types.Bridge(
            bridge_id=proto_entity.bridgeId, node_id=proto_entity.nodeId, wan_ip_enforcement=proto_entity.wanIpEnforcement,
            lan_ip_enforcement=proto_entity.lanIpEnforcement, status=proto_entity.status)


class ScimEntity(_IEnterpriseEntity[enterprise_types.Scim, int]):
    def get_entity_key(self, entity):
        return entity.scim_id

    def convert_entity(self, data):
        proto_entity = enterprise_pb2.Scim()
        proto_entity.ParseFromString(data)
        return enterprise_types.Scim(
            scim_id=proto_entity.scimId, node_id=proto_entity.nodeId, status=proto_entity.status, last_synced=proto_entity.lastSynced,
            role_prefix=proto_entity.rolePrefix, unique_groups=proto_entity.uniqueGroups)


class SsoServiceEntity(_IEnterpriseEntity[enterprise_types.SsoService, int]):
    def get_entity_key(self, entity):
        return entity.sso_service_provider_id

    def convert_entity(self, data):
        proto_entity = enterprise_pb2.SsoService()
        proto_entity.ParseFromString(data)
        return enterprise_types.SsoService(
            sso_service_provider_id=proto_entity.ssoServiceProviderId, node_id=proto_entity.nodeId, name=proto_entity.name,
            sp_url=proto_entity.sp_url, invite_new_users=proto_entity.inviteNewUsers, active=proto_entity.active,
            is_cloud=proto_entity.isCloud)


class EmailProvisionEntity(_IEnterpriseEntity[enterprise_types.EmailProvision, int]):
    def get_entity_key(self, entity):
        return entity.id

    def convert_entity(self, data):
        proto_entity = enterprise_pb2.EmailProvision()
        proto_entity.ParseFromString(data)
        return enterprise_types.EmailProvision(id=proto_entity.id, node_id=proto_entity.nodeId,
                                               domain=proto_entity.domain, method=proto_entity.method)

