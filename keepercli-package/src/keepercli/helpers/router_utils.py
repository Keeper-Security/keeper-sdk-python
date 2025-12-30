import logging
import google
from typing import Optional

from keepersdk.proto import pam_pb2
from keepersdk.vault import vault_online


API_PATH_GET_CONTROLLERS = "get_controllers"


def router_get_connected_gateways(vault: vault_online.VaultOnline) -> Optional[pam_pb2.PAMOnlineControllers]:
    """Get connected gateways from the router."""
    rs = vault.keeper_auth.keeper_endpoint.execute_router_rest(
        endpoint=API_PATH_GET_CONTROLLERS, 
        session_token=vault.keeper_auth.auth_context.session_token,
        payload=b''
    )

    if isinstance(rs, bytes):
        pam_online_controllers = pam_pb2.PAMOnlineControllers()
        pam_online_controllers.ParseFromString(rs)
        if logging.getLogger().level <= logging.DEBUG:
            js = google.protobuf.json_format.MessageToJson(pam_online_controllers)
            logging.debug('>>> [GW RS] %s: %s', API_PATH_GET_CONTROLLERS, js)

        return pam_online_controllers

    return None
