import os
import logging
import google
import requests
from typing import Optional, Tuple, Dict, Any

from .. import crypto, errors, utils
from ..authentication import endpoint
from ..proto import router_pb2, pam_pb2
from ..vault import vault_online


VERIFY_SSL = bool(os.environ.get("VERIFY_SSL", "TRUE") == "TRUE")
KROUTER_URL_ENV_VAR = "KROUTER_URL"
ROUTER_URL_PREFIX = "https://connect."
GOVCLOUD_SUBDOMAIN = ".govcloud."
API_USER_PATH_PREFIX = "/api/user/"
CONTENT_TYPE_HEADER = "Content-Type"
CONTENT_TYPE_JSON = "application/json"
TRANSMISSION_KEY_HEADER = "TransmissionKey"
API_PATH_GET_CONTROLLERS = "get_controllers"
ERROR_CODE_CONNECTION = "-1"


def get_router_url(vault: vault_online.VaultOnline) -> str:
    """Get the router URL from environment variable or construct from vault endpoint."""
    if os.getenv(KROUTER_URL_ENV_VAR):
        krouter_server_url = os.getenv(KROUTER_URL_ENV_VAR)
        logging.debug(f"Getting Krouter url from ENV Variable '{KROUTER_URL_ENV_VAR}'='{krouter_server_url}'")
        return krouter_server_url
    
    base_server = vault.keeper_auth.keeper_endpoint.server
    if isinstance(base_server, bytes):
        base_server = base_server.decode('utf-8')
    
    # In GovCloud environments, the router service is not under the govcloud subdomain
    krouter_server_url = ROUTER_URL_PREFIX + base_server
    if GOVCLOUD_SUBDOMAIN in krouter_server_url:
        krouter_server_url = krouter_server_url.replace(GOVCLOUD_SUBDOMAIN, ".")

    return krouter_server_url


def router_get_connected_gateways(vault: vault_online.VaultOnline) -> Optional[pam_pb2.PAMOnlineControllers]:
    """Get connected gateways from the router."""
    rs = _post_request_to_router(vault, API_PATH_GET_CONTROLLERS)

    if isinstance(rs, bytes):
        pam_online_controllers = pam_pb2.PAMOnlineControllers()
        pam_online_controllers.ParseFromString(rs)
        if logging.getLogger().level <= logging.DEBUG:
            js = google.protobuf.json_format.MessageToJson(pam_online_controllers)
            logging.debug('>>> [GW RS] %s: %s', API_PATH_GET_CONTROLLERS, js)

        return pam_online_controllers

    return None


def _prepare_transmission_key(vault: vault_online.VaultOnline, 
                              transmission_key: Optional[bytes] = None,
                              encrypted_transmission_key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Prepare transmission key and encrypted transmission key for the request."""
    if not transmission_key:
        transmission_key = utils.generate_aes_key()
    
    if not encrypted_transmission_key:
        server_key_id = vault.keeper_auth.keeper_endpoint.server_key_id
        server_public_key = endpoint.SERVER_PUBLIC_KEYS[server_key_id]

        if server_key_id < 7:
            encrypted_transmission_key = crypto.encrypt_rsa(transmission_key, server_public_key)
        else:
            encrypted_transmission_key = crypto.encrypt_ec(transmission_key, server_public_key)

    return transmission_key, encrypted_transmission_key


def _encrypt_request_payload(rq_proto, transmission_key: bytes) -> bytes:
    """Encrypt the request payload if provided."""
    if not rq_proto:
        return b''
    
    if logging.getLogger().level <= logging.DEBUG:
        js = google.protobuf.json_format.MessageToJson(rq_proto)
        logging.debug('>>> [GW RQ] %s: %s', rq_proto.__class__.__name__, js)
    
    return crypto.encrypt_aes_v2(rq_proto.SerializeToString(), transmission_key)


def _prepare_session_token(vault: vault_online.VaultOnline,
                          transmission_key: bytes,
                          encrypted_session_token: Optional[bytes] = None) -> bytes:
    """Prepare encrypted session token for the request."""
    if not encrypted_session_token:
        encrypted_session_token = crypto.encrypt_aes_v2(
            vault.keeper_auth.auth_context.session_token, 
            transmission_key
        )
    return encrypted_session_token


def _prepare_request_headers(encrypted_transmission_key: bytes, 
                             encrypted_session_token: bytes) -> Dict[str, str]:
    """Prepare HTTP request headers."""
    return {
        TRANSMISSION_KEY_HEADER: utils.base64_url_encode(encrypted_transmission_key),
        'Authorization': f'KeeperUser {utils.base64_url_encode(encrypted_session_token)}'
    }


def _execute_http_request(krouter_host: str, 
                          path: str,
                          method: str,
                          headers: Dict[str, str],
                          query_params: Optional[Dict] = None,
                          data: Optional[bytes] = None) -> requests.Response:
    """Execute HTTP request to the router."""
    full_url = krouter_host + path
    try:
        return requests.request(
            method,
            full_url,
            params=query_params,
            verify=VERIFY_SSL,
            headers=headers,
            data=data
        )
    except ConnectionError as e:
        raise errors.KeeperApiError(
            ERROR_CODE_CONNECTION, 
            f"KRouter is not reachable on '{krouter_host}'. Error: {e}"
        )


def _parse_router_response(rs: requests.Response,
                          transmission_key: bytes,
                          rs_type: Optional[type] = None,
                          path: str = "") -> Any:
    """Parse the router response based on content type and response type."""
    content_type = rs.headers.get(CONTENT_TYPE_HEADER) or ''
    
    if content_type == CONTENT_TYPE_JSON:
        return rs.json()

    rs_body = rs.content
    if not isinstance(rs_body, bytes):
        return rs_body

    router_response = router_pb2.RouterResponse()
    router_response.ParseFromString(rs_body)

    rrc = router_pb2.RouterResponseCode.Name(router_response.responseCode)
    if router_response.responseCode != router_pb2.RRC_OK:
        raise Exception(f"{router_response.errorMessage} Response code: {rrc}")

    payload_decrypted = None
    if router_response.encryptedPayload:
        payload_decrypted = crypto.decrypt_aes_v2(router_response.encryptedPayload, transmission_key)

    if rs_type:
        if payload_decrypted:
            rs_proto = rs_type()
            rs_proto.ParseFromString(payload_decrypted)
            if logging.getLogger().level <= logging.DEBUG:
                js = google.protobuf.json_format.MessageToJson(rs_proto)
                logging.debug('>>> [GW RS] %s: %s', path, js)
            return rs_proto
        return None

    return payload_decrypted


def _post_request_to_router(vault: vault_online.VaultOnline, 
                            path: str,
                            rq_proto=None, 
                            rs_type=None, 
                            method: str = 'post',
                            raw_without_status_check_response: bool = False, 
                            query_params: Optional[Dict] = None,
                            transmission_key: Optional[bytes] = None,
                            encrypted_transmission_key: Optional[bytes] = None, 
                            encrypted_session_token: Optional[bytes] = None):
    """Post a request to the router and return the response."""
    krouter_host = get_router_url(vault)
    full_path = API_USER_PATH_PREFIX + path

    transmission_key, encrypted_transmission_key = _prepare_transmission_key(
        vault, transmission_key, encrypted_transmission_key
    )
    
    encrypted_payload = _encrypt_request_payload(rq_proto, transmission_key)
    
    encrypted_session_token = _prepare_session_token(vault, transmission_key, encrypted_session_token)
    
    headers = _prepare_request_headers(encrypted_transmission_key, encrypted_session_token)
    
    rs = _execute_http_request(
        krouter_host,
        full_path,
        method,
        headers,
        query_params,
        encrypted_payload if rq_proto else None
    )

    if raw_without_status_check_response:
        return rs

    if rs.status_code < 400:
        return _parse_router_response(rs, transmission_key, rs_type, path)
    else:
        raise errors.KeeperApiError(str(rs.status_code), rs.text)
