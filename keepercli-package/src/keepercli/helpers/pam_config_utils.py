#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import logging

from keepersdk.helpers.tunnel.tunnel_graph import TunnelDAG, get_vertex_content
from keepersdk.helpers.tunnel.tunnel_utils import get_keeper_tokens

from ...params import KeeperParams


def _allowed_settings_dag_to_json(allowed_settings):
    if not isinstance(allowed_settings, dict):
        return {}
    return {
        'connections': allowed_settings.get('connections'),
        'tunneling': allowed_settings.get('tunneling'),
        'rotation': allowed_settings.get('rotation'),
    }


def pam_config_allowed_settings_json(params: KeeperParams, config_uid: str):
    try:
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params.vault)
        tmp_dag = TunnelDAG(
            params.vault, encrypted_session_token, encrypted_transmission_key, config_uid,
            is_config=True, transmission_key=transmission_key,
        )
        tmp_dag.linking_dag.load()
        vertex = tmp_dag.linking_dag.get_vertex(config_uid)
        content = get_vertex_content(vertex) if vertex else None
        allowed = (content or {}).get('allowedSettings') or {}
        return _allowed_settings_dag_to_json(allowed)
    except Exception as e:
        logging.getLogger(__name__).debug('PAM config allowedSettings: %s', e)
        return _allowed_settings_dag_to_json({})
