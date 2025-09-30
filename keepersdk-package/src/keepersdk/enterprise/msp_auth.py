from typing import Tuple

from . import enterprise_types
from ..proto import enterprise_pb2
from ..authentication import keeper_auth, login_auth
from .. import crypto, utils

def login_to_managed_company(loader: enterprise_types.IEnterpriseLoader, mc_enterprise_id: int) -> Tuple[keeper_auth.KeeperAuth, bytes]:
    auth = loader.keeper_auth
    tree_key = loader.enterprise_data.enterprise_info.tree_key
    rq = enterprise_pb2.LoginToMcRequest()
    rq.mcEnterpriseId = mc_enterprise_id
    rs = auth.execute_auth_rest('authentication/login_to_mc', rq, response_type=enterprise_pb2.LoginToMcResponse)
    assert rs is not None
    auth_context = keeper_auth.AuthContext()
    auth_context.username = auth.auth_context.username
    auth_context.account_uid = auth.auth_context.account_uid
    auth_context.data_key = auth.auth_context.data_key
    auth_context.device_token = auth.auth_context.device_token
    auth_context.device_private_key = auth.auth_context.device_private_key
    auth_context.session_token = rs.encryptedSessionToken
    encrypted_tree_key = utils.base64_url_decode(rs.encryptedTreeKey)
    mc_tree_key = crypto.decrypt_aes_v2(encrypted_tree_key, tree_key)
    mc_auth = keeper_auth.KeeperAuth(auth.keeper_endpoint, auth_context)
    mc_auth.post_login()

    return mc_auth, mc_tree_key

