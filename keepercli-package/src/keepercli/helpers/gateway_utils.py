from time import time
from typing import List

from keepersdk import utils
from keepersdk.vault import vault_online
from keepersdk.proto import pam_pb2, enterprise_pb2
from keepersdk.vault import ksm_management


# REST endpoint constants
REST_ENDPOINT_GET_CONTROLLERS = 'pam/get_controllers'
REST_ENDPOINT_REMOVE_CONTROLLER = 'pam/remove_controller'
REST_ENDPOINT_SET_MAX_INSTANCE_COUNT = 'pam/set_controller_max_instance_count'

# Dictionary key constants
KEY_TOKEN_INFO = 'token_info'
KEY_ONE_TIME_TOKEN = 'oneTimeToken'

# Time constants
MILLISECONDS_PER_SECOND = 1000
SECONDS_PER_MINUTE = 60
MILLISECONDS_PER_MINUTE = SECONDS_PER_MINUTE * MILLISECONDS_PER_SECOND
DEFAULT_OTT_EXPIRE_MINUTES = 5

# KSM client constants
KSM_CLIENT_COUNT = 1
KSM_CLIENT_INDEX = 0


def get_all_gateways(vault: vault_online.VaultOnline) -> List[pam_pb2.PAMController]:
    """Retrieve all PAM gateways from the vault."""
    rs = vault.keeper_auth.execute_auth_rest(
        REST_ENDPOINT_GET_CONTROLLERS, 
        None, 
        response_type=pam_pb2.PAMControllersResponse
    )
    if rs:
        return list(rs.controllers)
    return []


def _calculate_first_access_expire_time(ott_expire_in_min: int) -> int:
    """Calculate the first access expiration time in milliseconds."""
    current_time_ms = int(time() * MILLISECONDS_PER_SECOND)
    return current_time_ms + ott_expire_in_min * MILLISECONDS_PER_MINUTE


def _extract_one_time_token(token_dict: dict) -> str:
    """Extract the one-time token from the token dictionary."""
    return token_dict[KEY_TOKEN_INFO][KEY_ONE_TIME_TOKEN]


def create_gateway(
    vault: vault_online.VaultOnline, 
    gateway_name: str, 
    app_uid: str, 
    ott_expire_in_min: int = DEFAULT_OTT_EXPIRE_MINUTES
) -> str:
    """Create a new PAM gateway and return its one-time token."""
    master_key = vault.vault_data.get_record_key(record_uid=app_uid)
    first_access_expire_duration_ms = _calculate_first_access_expire_time(ott_expire_in_min)
    
    one_time_token_dict = ksm_management.KSMClientManagement.add_client_to_ksm_app(
        vault,
        uid=app_uid,
        client_name=gateway_name,
        count=KSM_CLIENT_COUNT,
        index=KSM_CLIENT_INDEX,
        unlock_ip=True,
        first_access_expire_duration_ms=first_access_expire_duration_ms,
        access_expire_in_ms=None,
        master_key=master_key,
        server=vault.keeper_auth.keeper_endpoint.server,
        client_type=enterprise_pb2.DISCOVERY_AND_ROTATION_CONTROLLER
    )

    return _extract_one_time_token(one_time_token_dict)


def _find_controller_by_uid(controllers, gateway_uid: bytes):
    """Find a controller by its UID."""
    return next((x for x in controllers if x.controllerUid == gateway_uid), None)


def _handle_remove_controller_response(rs, gateway_uid: bytes):
    """Handle the response from removing a controller and raise exception if needed."""
    if rs and rs.controllers:
        controller = _find_controller_by_uid(rs.controllers, gateway_uid)
        if controller:
            raise Exception(controller.message)


def remove_gateway(vault: vault_online.VaultOnline, gateway_uid: bytes):
    """Remove a PAM gateway by its UID."""
    rq = pam_pb2.PAMGenericUidRequest()
    rq.uid = gateway_uid
    rs = vault.keeper_auth.execute_auth_rest(
        rest_endpoint=REST_ENDPOINT_REMOVE_CONTROLLER,
        request=rq,
        response_type=pam_pb2.PAMRemoveControllerResponse
    )
    _handle_remove_controller_response(rs, gateway_uid)


def set_gateway_max_instances(vault: vault_online.VaultOnline, gateway_uid: bytes, max_instance_count: int):
    """Set the maximum instance count for a PAM gateway."""
    rq = pam_pb2.PAMSetMaxInstanceCountRequest()
    rq.controllerUid = gateway_uid
    rq.maxInstanceCount = max_instance_count
    vault.keeper_auth.execute_auth_rest(
        rest_endpoint=REST_ENDPOINT_SET_MAX_INSTANCE_COUNT,
        request=rq
    )


def find_connected_gateways(all_controllers, identifier):

    found_connected_controller_uid_bytes = next((c for c in all_controllers if (utils.base64_url_encode(c) == identifier)), None)

    if found_connected_controller_uid_bytes:
        return found_connected_controller_uid_bytes
    else:
        return None
