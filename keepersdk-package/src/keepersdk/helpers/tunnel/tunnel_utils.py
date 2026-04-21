import json
import os
import logging
import requests

from typing import Any, Dict, List, Optional

from ... import errors, utils, crypto
from ...vault import vault_online
from ..keeper_dag.dag_crypto import generate_random_bytes
from ...authentication import endpoint


logger = logging.getLogger(__name__)


VERIFY_SSL = bool(os.environ.get("VERIFY_SSL", "TRUE") == "TRUE")


def get_config_uid(vault: vault_online.VaultOnline, encrypted_session_token: bytes, encrypted_transmission_key: bytes, record_uid: str) -> Optional[str]:
    try:
        rs = get_dag_leafs(vault, encrypted_session_token, encrypted_transmission_key, record_uid)
        if not rs:
            return None
        else:
            return rs[0].get('value', '')
    except Exception as e:
        logger.error(f"Error getting configuration: {e}")
    return None


def get_dag_leafs(vault: vault_online.VaultOnline, encrypted_session_token: bytes, encrypted_transmission_key: bytes, record_id: str) -> Optional[List[Dict[str, Any]]]:
    """
    POST a stringified JSON object to /api/dag/get_leafs on the KRouter
    The object is:
    {
      vertex: string,
      graphId: number
    }
    """
    krouter_host = f"https://{vault.keeper_auth.keeper_endpoint.get_router_server()}"
    path = '/api/user/get_leafs'

    payload = {
        'vertex': record_id,
        'graphId': 0
    }

    try:
        rs = requests.request('post',
                              krouter_host + path,
                              verify=VERIFY_SSL,
                              headers={
                                  'TransmissionKey': utils.base64_url_encode(encrypted_transmission_key),
                                  'Authorization': f'KeeperUser {utils.base64_url_encode(encrypted_session_token)}'
                              },
                              data=json.dumps(payload).encode('utf-8')
                              )
    except ConnectionError as e:
        raise errors.KeeperApiError(-1, f"KRouter is not reachable on '{krouter_host}'. Error: ${e}")
    except Exception as ex:
        raise ex

    if rs.status_code == 200:
        logger.debug("Found right host")
        return rs.json()
    else:
        logger.warning("Looks like there is no such controller connected to the router.")
        return None
    

def get_keeper_tokens(vault: vault_online.VaultOnline):
    transmission_key = generate_random_bytes(32)
    server_public_key = endpoint.SERVER_PUBLIC_KEYS[vault.keeper_auth.keeper_endpoint.server_key_id]

    if vault.keeper_auth.keeper_endpoint.server_key_id < 7:
        encrypted_transmission_key = crypto.encrypt_rsa(transmission_key, server_public_key)
    else:
        encrypted_transmission_key = crypto.encrypt_ec(transmission_key, server_public_key)
    encrypted_session_token = crypto.encrypt_aes_v2(
        vault.keeper_auth.auth_context.session_token, transmission_key)

    return encrypted_session_token, encrypted_transmission_key, transmission_key
