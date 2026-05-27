#!/usr/bin/env python3
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK for Python
# Copyright 2025 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example: msp_convert_node() — convert an enterprise subtree into a managed company.
#

from typing import Optional

from keepersdk.enterprise import msp_auth

from msp_common import close_loader_and_auth, login_with_enterprise

NODE_NAME_OR_ID = 'root'
SEATS: Optional[int] = None
PLAN: Optional[str] = None


def _resolve_node_id(loader, node_arg: str) -> int:
    enterprise_data = loader.enterprise_data
    if node_arg.isdigit():
        node = enterprise_data.nodes.get_entity(int(node_arg))
        if node is None:
            raise ValueError(f'Node id {node_arg} not found')
        return node.node_id
    key = node_arg.lower()
    for node in enterprise_data.nodes.get_all_entities():
        if node.name and node.name.lower() == key:
            return node.node_id
    root = enterprise_data.root_node
    if key == 'root':
        return root.node_id
    raise ValueError(f'Node "{node_arg}" not found')


def main():
    auth, loader = login_with_enterprise()
    if not auth or not loader:
        print('Login failed.')
        return
    try:
        msp_auth.msp_down(loader, reset=False)
        node_id = _resolve_node_id(loader, NODE_NAME_OR_ID)
        mc_id = msp_auth.msp_convert_node(
            loader,
            node_id=node_id,
            seats=SEATS,
            plan=PLAN,
        )
        print(f'Converted node {NODE_NAME_OR_ID} to managed company id={mc_id}.')
    finally:
        close_loader_and_auth(loader, auth)


if __name__ == '__main__':
    main()
