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

from ..params import KeeperParams


class _CachedRecord:
    def __init__(self, record_uid: str, title: str = ''):
        self.record_uid = record_uid
        self.title = title


def get_record(params: KeeperParams, record_uid: str):
    record_uid = (record_uid or '').strip()
    if not record_uid or params.vault is None:
        logging.warning('No record UID provided')
        return None
    info = params.vault.vault_data.get_record(record_uid)
    if info:
        return _CachedRecord(info.record_uid, info.title)
    kr = params.vault.vault_data.load_record(record_uid)
    if kr:
        return _CachedRecord(record_uid, getattr(kr, 'title', '') or '')
    logging.warning('Record UID %s not found in cache.', record_uid)
    return None
