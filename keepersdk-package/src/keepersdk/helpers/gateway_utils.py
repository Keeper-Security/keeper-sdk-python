import secrets
import string
from time import time
from typing import List, Tuple

from ..authentication import endpoint
from .. import crypto, utils
from ..vault import vault_online
from ..proto import pam_pb2
from ..vault import ksm_management


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

# Key generation constants
SYMMETRIC_KEY_LENGTH = 32
RANDOM_LENGTH = SYMMETRIC_KEY_LENGTH
SERVER_KEY_ID_RSA_THRESHOLD = 7

# KSM client constants
KSM_CLIENT_COUNT = 1
KSM_CLIENT_INDEX = 0

# Byte filtering constants
FILTERED_BYTES = b'\n\r'


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
        server=vault.keeper_auth.keeper_endpoint.server
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


def _get_server_public_key(vault: vault_online.VaultOnline):
    """Retrieve the server public key for the current endpoint."""
    server_key_id = vault.keeper_auth.keeper_endpoint.server_key_id
    return endpoint.SERVER_PUBLIC_KEYS[server_key_id]


def _encrypt_transmission_key(transmission_key: bytes, server_public_key, server_key_id: int) -> bytes:
    """Encrypt the transmission key using RSA or EC based on server key ID."""
    if server_key_id < SERVER_KEY_ID_RSA_THRESHOLD:
        return crypto.encrypt_rsa(transmission_key, server_public_key)
    return crypto.encrypt_ec(transmission_key, server_public_key)


def _encrypt_session_token(session_token: str, transmission_key: bytes) -> bytes:
    """Encrypt the session token using AES v2."""
    decoded_token = utils.base64_url_decode(session_token)
    return crypto.encrypt_aes_v2(decoded_token, transmission_key)


def get_keeper_tokens(vault: vault_online.VaultOnline) -> Tuple[bytes, bytes, bytes]:
    """Generate and encrypt keeper tokens for authentication."""
    transmission_key = generate_random_bytes(SYMMETRIC_KEY_LENGTH)
    server_public_key = _get_server_public_key(vault)
    server_key_id = vault.keeper_auth.keeper_endpoint.server_key_id
    
    encrypted_transmission_key = _encrypt_transmission_key(
        transmission_key, 
        server_public_key, 
        server_key_id
    )
    encrypted_session_token = _encrypt_session_token(
        vault.keeper_auth.auth_context.session_token,
        transmission_key
    )

    return encrypted_session_token, encrypted_transmission_key, transmission_key


def _is_printable_byte(byte: int) -> bool:
    """Check if a byte is printable and not a newline or carriage return."""
    printable_encoding = string.printable.encode('utf-8')
    return byte in printable_encoding and byte not in FILTERED_BYTES


def _filter_printable_bytes(random_bytes: bytes) -> bytes:
    """Filter bytes to only include printable characters excluding newlines."""
    printable_bytes = [byte for byte in random_bytes if _is_printable_byte(byte)]
    return bytes(printable_bytes)


def generate_random_bytes(pass_length: int = RANDOM_LENGTH) -> bytes:
    """Generate random bytes containing only printable characters."""
    random_bytes = secrets.token_bytes(pass_length)
    filtered_bytes = _filter_printable_bytes(random_bytes)
    
    if len(filtered_bytes) < pass_length:
        remaining_length = pass_length - len(filtered_bytes)
        return filtered_bytes + generate_random_bytes(remaining_length)

    return filtered_bytes


