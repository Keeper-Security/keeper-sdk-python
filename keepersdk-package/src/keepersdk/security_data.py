"""
Security Data Management Module

This module provides functionality for managing security audit data for Keeper records,
including password strength scoring, breach watch status, and security data encryption.
"""

import json
import logging
import urllib.parse
from typing import Union, List, Dict, Optional, Set, Any

from . import utils, crypto
from .vault import vault_online, vault_record
from .proto import APIRequest_pb2, client_pb2, record_pb2

logger = logging.getLogger(__name__)


def has_passkey(record: vault_record.KeeperRecord) -> bool:
    """
    Check if a record has a passkey field with a value.
    
    Args:
        record: Keeper record to check
        
    Returns:
        True if the record has a passkey value, False otherwise
    """
    if not isinstance(record, vault_record.TypedRecord):
        return False
    
    passkey_field = record.get_typed_field('passkey')
    if not passkey_field:
        return False
    
    return bool(passkey_field.value)


def get_password(record: vault_record.KeeperRecord) -> Optional[str]:
    """
    Extract password from a Keeper record.
    
    Args:
        record: Keeper record
        
    Returns:
        Password string or None if no password exists
    """
    if isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
        return record.extract_password() or None
    return None


def get_security_score(record: vault_record.KeeperRecord) -> Optional[int]:
    """
    Calculate security score for a record.
    
    Returns 100 if passkey exists, otherwise returns password strength score.
    Returns None if neither password nor passkey exists.
    
    Args:
        record: Keeper record
        
    Returns:
        Security score (0-100) or None
    """
    password = get_password(record)
    if not password:
        return 100 if has_passkey(record) else None
    
    score = utils.password_score(password)
    # If passkey exists, return perfect score regardless of password
    return 100 if has_passkey(record) else score


def is_password_strong(score: int) -> bool:
    """
    Determine if a password is strong based on its score.
    
    Args:
        score: Password strength score (0-100)
        
    Returns:
        True if password is considered strong (score >= 60)
    """
    return score >= 60


def encrypt_security_data(vault: vault_online.VaultOnline, data: Dict[str, Any]) -> bytes:
    """
    Encrypt security data using enterprise public key.
    
    Args:
        vault: VaultOnline instance
        data: Security data dictionary to encrypt
        
    Returns:
        Encrypted data bytes
        
    Raises:
        Exception: If enterprise key is not available
    """
    auth_context = vault.keeper_auth.auth_context
    
    if auth_context.forbid_rsa and not auth_context.enterprise_ec_public_key:
        raise Exception('Enterprise ECC public key is not available')
    
    if not auth_context.forbid_rsa and not auth_context.enterprise_rsa_public_key:
        raise Exception('Enterprise RSA public key is not available')
    
    data_bytes = json.dumps(data).encode('utf8')
    
    if auth_context.forbid_rsa:
        return crypto.encrypt_ec(data_bytes, auth_context.enterprise_ec_public_key)
    else:
        return crypto.encrypt_rsa(data_bytes, auth_context.enterprise_rsa_public_key)


def prepare_security_data(vault: vault_online.VaultOnline, record: vault_record.KeeperRecord) -> bytes:
    """
    Prepare encrypted security data for a record.
    
    Args:
        vault: VaultOnline instance
        record: Keeper record
        
    Returns:
        Encrypted security data bytes (empty if no security data)
    """
    score = get_security_score(record)
    
    # Send empty data to remove old security data (when password and/or passkey are removed)
    if score is None:
        return b''
    
    sec_data = {'strength': score}
    password = get_password(record)
    
    # Extract URL and domain
    url = record.extract_url() if isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)) else None
    if url:
        parse_results = urllib.parse.urlparse(url)
        domain = parse_results.hostname or parse_results.path
        
        # Get breach watch status
        bw_record = vault.vault_data.get_breach_watch_record(record.record_uid)
        if bw_record and password:
            status = bw_record.status
            if status:
                sec_data['bw_result'] = int(status)
            else:
                sec_data['bw_result'] = (
                    int(client_pb2.BWStatus.GOOD) if is_password_strong(score) 
                    else int(client_pb2.BWStatus.WEAK)
                )
        
        if domain:
            # Check data size to avoid RSA encryption size limitation
            data_size = len(json.dumps(sec_data).encode('utf8'))
            max_size = 244
            diff = max_size - data_size
            
            # Truncate domain string if needed
            if diff < 0:
                new_length = len(domain) + diff
                sec_data['domain'] = domain[:new_length]
            else:
                sec_data['domain'] = domain
    
    return encrypt_security_data(vault, sec_data)


def prepare_security_data_update(
    vault: vault_online.VaultOnline, 
    record: vault_record.KeeperRecord
) -> Optional[APIRequest_pb2.SecurityData]:
    """
    Prepare SecurityData protobuf message for API update.
    
    Args:
        vault: VaultOnline instance
        record: Keeper record
        
    Returns:
        SecurityData protobuf message or None on error
    """
    sd = APIRequest_pb2.SecurityData()
    try:
        sd.uid = utils.base64_url_decode(record.record_uid)
        data = prepare_security_data(vault, record)
        if data:
            sd.data = data
        return sd
    except Exception as e:
        logger.error(f'Could not update security data for record {record.record_uid}: {e}')
        return None


def prepare_score_data(record: vault_record.KeeperRecord, record_key: bytes) -> bytes:
    """
    Prepare encrypted security score data for a record.
    
    Args:
        record: Keeper record
        record_key: Record encryption key
        
    Returns:
        Encrypted score data bytes
    """
    empty_score_data = crypto.encrypt_aes_v2(json.dumps({}).encode('utf8'), record_key)
    score = get_security_score(record)
    
    if score is None:
        return empty_score_data
    
    try:
        password = get_password(record) or ''
        # Add padding for security (obfuscate password length)
        pad_length = max(25 - len(password), 0) if password else 0
        pad = ' ' * pad_length
        
        score_data = {
            'version': 1,
            'password': password,
            'score': score,
            'padding': pad
        }
        
        data = json.dumps(score_data).encode('utf-8')
        return crypto.encrypt_aes_v2(data, record_key)
    except Exception as e:
        logger.error(f'Could not calculate security score data for record {record.record_uid}: {e}')
        return empty_score_data


def prepare_score_data_update(
    vault: vault_online.VaultOnline,
    record: vault_record.KeeperRecord
) -> APIRequest_pb2.SecurityScoreData:
    """
    Prepare SecurityScoreData protobuf message for API update.
    
    Args:
        vault: VaultOnline instance
        record: Keeper record
        
    Returns:
        SecurityScoreData protobuf message
    """
    ssd = APIRequest_pb2.SecurityScoreData()
    ssd.uid = utils.base64_url_decode(record.record_uid)
    
    record_key = vault.vault_data.get_record_key(record.record_uid)
    if record_key:
        ssd.data = prepare_score_data(record, record_key)
    
    # Try to get existing revision from storage
    try:
        security_score_record = vault.vault_data.storage.security_score_data.get_entity(record.record_uid)
        if security_score_record and hasattr(security_score_record, 'revision'):
            ssd.revision = security_score_record.revision
    except Exception:
        pass  # No existing revision
    
    return ssd


def needs_security_audit(vault: vault_online.VaultOnline, record: vault_record.KeeperRecord) -> bool:
    """
    Determine if a record needs security audit data update.
    
    Args:
        vault: VaultOnline instance
        record: Keeper record
        
    Returns:
        True if security audit is needed, False otherwise
    """
    auth_context = vault.keeper_auth.auth_context
    if not (auth_context.enterprise_ec_public_key or auth_context.enterprise_rsa_public_key):
        return False
    
    if not record:
        return False
    
    # Get saved score data
    saved_score_data = {}
    try:
        security_score_record = vault.vault_data.storage.security_score_data.get_entity(record.record_uid)
        if security_score_record:
            record_key = vault.vault_data.get_record_key(record.record_uid)
            if record_key and security_score_record.data:
                decrypted_data = crypto.decrypt_aes_v2(security_score_record.data, record_key)
                saved_score_data = json.loads(decrypted_data.decode('utf-8'))
    except Exception:
        pass  # No saved score data
    
    # Check if password changed
    current_password = get_password(record) or None
    saved_password = saved_score_data.get('password') or None
    if current_password != saved_password:
        return True
    
    # Check if score changed significantly (e.g., passkey added/removed)
    current_score = get_security_score(record) or 0
    saved_score = saved_score_data.get('score', 0)
    
    # Detect passkey changes (score moved to/from 100)
    score_changed_on_passkey = (
        (current_score >= 100 and saved_score < 100) or 
        (current_score < 100 and saved_score >= 100)
    )
    
    # Detect credential removal
    creds_removed = bool(saved_score and not current_score)
    
    # Check if security data exists but score data doesn't (needs alignment)
    saved_sec_data = vault.vault_data.storage.breach_watch_security_data.get_entity(record.record_uid)
    needs_alignment = bool(current_score and not saved_sec_data)
    
    return score_changed_on_passkey or creds_removed or needs_alignment


def get_security_data_key_type(vault: vault_online.VaultOnline) -> int:
    """
    Get the security data encryption key type.
    
    Args:
        vault: VaultOnline instance
        
    Returns:
        Encryption type constant from record_pb2
    """
    auth_context = vault.keeper_auth.auth_context
    return (
        record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC if auth_context.forbid_rsa 
        else record_pb2.ENCRYPTED_BY_PUBLIC_KEY
    )


def update_security_audit_data(
    vault: vault_online.VaultOnline,
    records: List[vault_record.KeeperRecord],
    quiet: bool = False
) -> int:
    """
    Update security audit data for multiple records.
    
    Args:
        vault: VaultOnline instance
        records: List of Keeper records to update
        quiet: If True, suppress progress messages
        
    Returns:
        Number of records successfully updated
    """
    auth_context = vault.keeper_auth.auth_context
    if not (auth_context.enterprise_ec_public_key or auth_context.enterprise_rsa_public_key):
        if not quiet:
            logger.warning('Enterprise public key not available. Cannot update security audit data.')
        return 0
    
    update_limit = 1000
    total_updates = len(records)
    failed_updates = []
    
    while records:
        chunk = records[:update_limit]
        records = records[update_limit:]
        
        rq = APIRequest_pb2.SecurityDataRequest()
        rq.encryptionType = get_security_data_key_type(vault)
        
        try:
            # Prepare security data updates
            sec_data_objs = (prepare_security_data_update(vault, rec) for rec in chunk)
            rq.recordSecurityData.extend(sd for sd in sec_data_objs if sd)
            
            # Prepare score data updates
            score_data_objs = (prepare_score_data_update(vault, rec) for rec in chunk)
            rq.recordSecurityScoreData.extend(sd for sd in score_data_objs if sd)
            
            # Send update request
            vault.keeper_auth.execute_auth_rest('enterprise/update_security_data', rq)
            
            if not quiet:
                logger.info(f'Updated security data for {len(chunk)} record(s)')
        except Exception as e:
            logger.error(f'Failed to update security data batch: {e}')
            failed_updates.extend(chunk)
    
    if failed_updates:
        logger.error(f'Could not update security data for {len(failed_updates)} record(s)')
    
    return total_updates - len(failed_updates)


def attach_security_data(
    vault: vault_online.VaultOnline,
    record: Union[str, Dict[str, Any], vault_record.KeeperRecord],
    rq_param: Union[record_pb2.RecordUpdate, record_pb2.RecordAdd]
) -> Union[record_pb2.RecordUpdate, record_pb2.RecordAdd]:
    """
    Attach security data to a record add/update request.
    
    Args:
        vault: VaultOnline instance
        record: Record UID, dict, or KeeperRecord instance
        rq_param: RecordUpdate or RecordAdd protobuf message
        
    Returns:
        Updated protobuf message with security data attached
    """
    try:
        # Convert to KeeperRecord if needed
        if not isinstance(record, vault_record.KeeperRecord):
            if isinstance(record, dict):
                record['version'] = record.get('version', 3)
            record = vault.vault_data.load_record(record if isinstance(record, str) else record.get('record_uid'))
        
        if record and needs_security_audit(vault, record):
            rq_param.securityData.data = prepare_security_data(vault, record)
            record_key = vault.vault_data.get_record_key(record.record_uid)
            if record_key:
                rq_param.securityScoreData.data = prepare_score_data(record, record_key)
    except Exception as e:
        logger.debug(f'Could not attach security data: {e}')
    finally:
        return rq_param

