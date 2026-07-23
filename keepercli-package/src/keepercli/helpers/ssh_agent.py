#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import io
import itertools
import logging
from typing import Optional, Tuple, Any, Union

from keepersdk.vault import attachment, vault_record

from ..compat import vault
from ..params import KeeperParams

# Accept both keepersdk and compat TypedRecord/FileRecord (compat subclasses keepersdk).
_TypedRecord = vault_record.TypedRecord
_FileRecord = vault_record.FileRecord
_PasswordRecord = vault_record.PasswordRecord
_KeeperRecord = vault_record.KeeperRecord

def is_private_key(header):   # type: (str) -> bool
    header = header.rstrip('\r\n')
    header = header.strip('-')
    if header.startswith('BEGIN') and header.endswith('PRIVATE KEY'):
        return True
    return False

Key_Prefix = ['id_']
Key_Suffix = ['.key', '.pem']
Key_Suffix_Exclude = ['.pub']
def is_private_key_name(name):     # type: (str) -> bool
    if not name:
        return False
    if isinstance(name, str):
        name = name.lower()
        if any(True for x in Key_Suffix_Exclude if name.endswith(x)):
            return False
        if any(True for x in Key_Suffix if name.endswith(x)):
            return True
        if any(True for x in Key_Prefix if name.startswith(x)):
            return True

    return False

KEY_SIZE_MIN = 119 # Smallest possible size for ed25519 private key in PKCS#8 format
# PEM bodies for large RSA keys (8192+) exceed 4K; keep a generous cap for sanity.
KEY_SIZE_MAX = 4000
PEM_TEXT_MAX = 256 * 1024


def _normalize_typed_field_label(label):
    # type: (Any) -> str
    if not label or not isinstance(label, str):
        return ''
    return ''.join(c.lower() for c in label if c.isalnum())


# Vault/PAM pamUser often stores PEM in a secret field labeled privatePEMKey (or similar).
_PEM_SECRET_FIELD_LABELS = frozenset({
    'privatepemkey',
    'sshprivatekey',
    'sshkeypem',
})


def _coerce_str_field_value(value):
    # type: (Any) -> Optional[str]
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8')
        except Exception:
            return None
    if isinstance(value, str):
        return value
    return None


def is_valid_key_value(value):
    return isinstance(value, str) and KEY_SIZE_MIN <= len(value) < KEY_SIZE_MAX


def _is_plausible_pem_private_key_blob(text):
    # type: (Optional[str]) -> bool
    text = _coerce_str_field_value(text)
    if not text:
        return False
    text = text.strip()
    if len(text) < KEY_SIZE_MIN or len(text) > PEM_TEXT_MAX:
        return False
    header, _, _ = text.partition('\n')
    return bool(is_private_key(header))


def is_valid_key_file(file):
    try:
        return KEY_SIZE_MIN <= file.size < PEM_TEXT_MAX
    except:
        return False

def try_extract_private_key(params, record_or_uid):
    # type: (KeeperParams, Union[str, vault.KeeperRecord]) -> Optional[Tuple[str, str]]
    if isinstance(record_or_uid, _KeeperRecord):
        record = record_or_uid
    elif isinstance(record_or_uid, str):
        record = vault.KeeperRecord.load(params, record_or_uid)
        if not record:
            return
    else:
        return

    private_key = ''
    passphrase = ''

    # check keyPair field
    if isinstance(record, _TypedRecord):
        key_field = record.get_typed_field('keyPair')
        if key_field:
            key_pair = key_field.get_default_value(value_type=dict)
            if key_pair:
                private_key = key_pair.get('privateKey')

    # Explicit PEM secret fields (pamUser template: type secret, label privatePEMKey, etc.)
    if not private_key and isinstance(record, _TypedRecord):
        for fld in itertools.chain(record.fields, record.custom):
            if _normalize_typed_field_label(getattr(fld, 'label', None)) not in _PEM_SECRET_FIELD_LABELS:
                continue
            candidate = _coerce_str_field_value(fld.get_default_value())
            if _is_plausible_pem_private_key_blob(candidate):
                private_key = candidate.strip()
                break

    # check notes field
    if not private_key:
        if isinstance(record, (_PasswordRecord, _TypedRecord)):
            notes = getattr(record, 'notes', None)
            if _is_plausible_pem_private_key_blob(notes):
                private_key = notes.strip()

    # check typed fields / custom (text, multiline, secret, note)
    if not private_key:
        if isinstance(record, _TypedRecord):
            for x in itertools.chain(record.fields, record.custom):
                if x.type not in ('text', 'multiline', 'secret', 'note'):
                    continue
                candidate = _coerce_str_field_value(x.get_default_value())
                if _is_plausible_pem_private_key_blob(candidate):
                    private_key = candidate.strip()
                    break
        elif isinstance(record, _PasswordRecord):
            for cf in record.custom:
                if not cf.value:
                    continue
                candidate = _coerce_str_field_value(cf.value[0] if isinstance(cf.value, list) and cf.value else cf.value)
                if _is_plausible_pem_private_key_blob(candidate):
                    private_key = candidate.strip()
                    break

    # check for a single attachment
    if not private_key:
        download_rq = None
        if isinstance(record, _TypedRecord):
            file_refs = record.get_typed_field('fileRef')
            if file_refs and isinstance(file_refs.value, list):
                key_file_uids = []
                for file_uid in file_refs.value:
                    file_record = vault.KeeperRecord.load(params, file_uid)
                    if isinstance(file_record, _FileRecord):
                        names = [file_record.title]
                        file_name = getattr(file_record, 'name', None) or getattr(file_record, 'file_name', None)
                        if file_name and file_name != file_record.title:
                            names.append(file_name)
                        if any(True for x in names if is_private_key_name(x)):
                            if is_valid_key_file(file_record):
                                key_file_uids.append(file_uid)
                if len(key_file_uids) == 1:
                    download_rq = next(attachment.prepare_attachment_download(params.vault, key_file_uids[0]), None)
        elif isinstance(record, _PasswordRecord):
            key_attachment_ids = []
            if record.attachments:
                for atta in record.attachments:
                    names = []
                    if atta.title:
                        names.append(atta.title)
                    if atta.name and atta.title != atta.name:
                        names.append(atta.name)
                    if any(True for x in names if is_private_key_name(x)):
                        if is_valid_key_file(atta):
                            key_attachment_ids.append(atta.id)
            if len(key_attachment_ids) == 1:
                download_rq = next(attachment.prepare_attachment_download(params.vault, record.record_uid, key_attachment_ids[0]), None)
        if download_rq:
            try:
                with io.BytesIO() as b:
                    download_rq.download_to_stream(b)
                    text = b.getvalue().decode('ascii')
                    header, _, _ = text.partition('\n')
                    if is_private_key(header):
                        private_key = text
            except:
                pass

    if isinstance(record, _PasswordRecord):
        passphrase = record.password
    elif isinstance(record, _TypedRecord):
        password_field = record.get_typed_field('password')
        if password_field:
            passphrase = password_field.get_default_value(str)

    if private_key:
        return private_key, passphrase
