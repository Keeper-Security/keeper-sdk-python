import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, List, Tuple, Any

from keepersdk import crypto, utils
from keepersdk.authentication import keeper_auth
from keepersdk.enterprise import enterprise_types

logger = logging.getLogger(__name__)


# Constants for encryption types
class EncryptionType(Enum):
    ENCRYPTED_BY_DATA_KEY = 'encrypted_by_data_key'
    ENCRYPTED_BY_PUBLIC_KEY = 'encrypted_by_public_key'
    ENCRYPTED_BY_DATA_KEY_GCM = 'encrypted_by_data_key_gcm'
    ENCRYPTED_BY_PUBLIC_KEY_ECC = 'encrypted_by_public_key_ecc'


# Transfer data keys
class TransferDataKeys(Enum):
    RECORD_KEYS = 'record_keys'
    CORRUPTED_RECORD_KEYS = 'corrupted_record_keys'
    SHARED_FOLDER_KEYS = 'shared_folder_keys'
    CORRUPTED_SHARED_FOLDER_KEYS = 'corrupted_shared_folder_keys'
    TEAM_KEYS = 'team_keys'
    CORRUPTED_TEAM_KEYS = 'corrupted_team_keys'
    USER_FOLDER_KEYS = 'user_folder_keys'
    CORRUPTED_USER_FOLDER_KEYS = 'corrupted_user_folder_keys'
    USER_FOLDER_TRANSFER = 'user_folder_transfer'

class TransferKeyType(Enum):
    RAW_DATA_KEY = 0
    ENCRYPTED_BY_DATA_KEY = 1
    ENCRYPTED_BY_RSA = 2
    ENCRYPTED_BY_DATA_KEY_GCM = 3
    ENCRYPTED_BY_ECC = 4


@dataclass
class PreTransferResponse:
    transfer_key2: Optional[bytes] = None
    transfer_key2_type_id: Optional[int] = None
    transfer_key: Optional[bytes] = None
    transfer_key_type_id: Optional[int] = None
    role_key: Optional[bytes] = None
    role_key_id: Optional[int] = None
    role_private_key: Optional[bytes] = None
    user_private_key: Optional[bytes] = None
    user_ecc_private_key: Optional[bytes] = None
    record_keys: List[Dict[str, Any]] = field(default_factory=list)
    shared_folder_keys: List[Dict[str, Any]] = field(default_factory=list)
    team_keys: List[Dict[str, Any]] = field(default_factory=list)
    user_folder_keys: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class TransferResult:
    success: bool
    username: str
    records_transferred: int = 0
    shared_folders_transferred: int = 0
    teams_transferred: int = 0
    user_folders_transferred: int = 0
    corrupted_records: int = 0
    corrupted_shared_folders: int = 0
    corrupted_teams: int = 0
    corrupted_user_folders: int = 0
    error_message: Optional[str] = None


class AccountTransferError(Exception):
    """Exception raised during account transfer operations"""


class AccountTransferManager:
    
    def __init__(self,
                 loader: enterprise_types.IEnterpriseLoader,
                 auth: keeper_auth.KeeperAuth):
        self.loader = loader
        self.auth = auth
    
    def transfer_account(self,
                        from_username: str,
                        to_username: str,
                        target_public_keys: keeper_auth.UserKeys) -> TransferResult:
                        
        try:
            logger.info(f'Starting account transfer from {from_username} to {to_username}')
            
            pre_transfer = self._execute_pre_transfer(from_username)
            
            user_data_key = self._decrypt_user_data_key(pre_transfer)
            
            user_rsa_private_key = self._decrypt_user_rsa_key(pre_transfer, user_data_key)
            user_ecc_private_key = self._decrypt_user_ecc_key(pre_transfer, user_data_key)
            
            transfer_data = self._prepare_transfer_data(
                pre_transfer,
                user_data_key,
                user_rsa_private_key,
                user_ecc_private_key,
                target_public_keys,
                from_username
            )
            
            result = self._execute_transfer(from_username, to_username, transfer_data)
            
            logger.info(f'Account transfer completed successfully for {from_username}')
            return result
            
        except Exception as e:
            raise AccountTransferError(f'Failed to transfer {from_username}: {e}') from e
    
    def _execute_pre_transfer(self, username: str) -> PreTransferResponse:
        rq = {
            'command': 'pre_account_transfer',
            'target_username': username
        }
        
        rs = self.auth.execute_auth_command(rq)
        return self._parse_pre_transfer_response(rs)
    
    def _parse_pre_transfer_response(self, rs: Dict) -> PreTransferResponse:
        """Parse pre_account_transfer response into dataclass"""
        # Keys that need base64 decoding
        base64_keys = ['transfer_key2', 'transfer_key', 'role_key', 'role_private_key', 
                      'user_private_key', 'user_ecc_private_key']
        
        decoded_data = {
            key: utils.base64_url_decode(rs[key]) if key in rs else None
            for key in base64_keys
        }
        
        decoded_data.update({
            'transfer_key2_type_id': rs.get('transfer_key2_type_id'),
            'transfer_key_type_id': rs.get('transfer_key_type_id'),
            'role_key_id': rs.get('role_key_id'),
            'record_keys': rs.get('record_keys', []),
            'shared_folder_keys': rs.get('shared_folder_keys', []),
            'team_keys': rs.get('team_keys', []),
            'user_folder_keys': rs.get('user_folder_keys', [])
        })
        
        return PreTransferResponse(**decoded_data)
    
    def _decrypt_user_data_key(self, pre_transfer: PreTransferResponse) -> bytes:

        if pre_transfer.transfer_key2:
            return self._decrypt_transfer_key2(
                pre_transfer.transfer_key2,
                pre_transfer.transfer_key2_type_id
            )
        

        if pre_transfer.transfer_key:
            return self._decrypt_legacy_transfer_key(pre_transfer)
        
        raise AccountTransferError('No valid transfer key found in response')
    
    def _decrypt_transfer_key2(self, encrypted_key: bytes, key_type: int) -> bytes:
        
        enterprise_data = self.loader.enterprise_data
        tree_key = enterprise_data.enterprise_info.tree_key
        
        if key_type == TransferKeyType.ENCRYPTED_BY_DATA_KEY.value:
            return crypto.decrypt_aes_v1(encrypted_key, tree_key)
        
        elif key_type == TransferKeyType.ENCRYPTED_BY_RSA.value:
            private_key = enterprise_data.enterprise_info.rsa_private_key
            if not private_key:
                raise AccountTransferError('Enterprise RSA private key not available')
            return crypto.decrypt_rsa(encrypted_key, private_key)
        
        elif key_type == TransferKeyType.ENCRYPTED_BY_DATA_KEY_GCM.value:
            return crypto.decrypt_aes_v2(encrypted_key, tree_key)
        
        elif key_type == TransferKeyType.ENCRYPTED_BY_ECC.value:
            private_key = enterprise_data.enterprise_info.ec_private_key
            if not private_key:
                raise AccountTransferError('Enterprise ECC private key not available')
            return crypto.decrypt_ec(encrypted_key, private_key)
        
        raise AccountTransferError(f'Unsupported transfer key type: {key_type}')
    
    def _decrypt_legacy_transfer_key(self, pre_transfer: PreTransferResponse) -> bytes:
        loader = self.loader

        role_key = None
        if pre_transfer.role_key:
            rsa_private_key = self.auth.auth_context.rsa_private_key
            if not rsa_private_key:
                raise AccountTransferError('RSA private key not available for role key decryption')
            role_key = crypto.decrypt_rsa(
                pre_transfer.role_key,
                rsa_private_key)
        elif pre_transfer.role_key_id:
            role_key_id = pre_transfer.role_key_id
            loader.load_role_keys([role_key_id])
            role_key = loader.get_role_keys(role_key_id)

        if not role_key:
            raise AccountTransferError('Cannot decrypt role key')
        
        if not pre_transfer.role_private_key:
            raise AccountTransferError('Role private key not found in response')
        
        role_private_key_bytes = crypto.decrypt_aes_v1(
            pre_transfer.role_private_key, role_key)
        role_private_key = crypto.load_rsa_private_key(role_private_key_bytes)
        
        return crypto.decrypt_rsa(pre_transfer.transfer_key, role_private_key)
        
    def _decrypt_user_rsa_key(self,
                              pre_transfer: PreTransferResponse,
                              user_data_key: bytes) -> Optional[Any]:
        user_private_key = pre_transfer.user_private_key
        if not user_private_key:
            return None
        
        decrypted = crypto.decrypt_aes_v1(
            user_private_key, user_data_key)
        return crypto.load_rsa_private_key(decrypted)
    
    def _decrypt_user_ecc_key(self,
                              pre_transfer: PreTransferResponse,
                              user_data_key: bytes) -> Optional[Any]:
        user_ecc_private_key = pre_transfer.user_ecc_private_key
        if not user_ecc_private_key:
            return None
        
        decrypted = crypto.decrypt_aes_v2(
            user_ecc_private_key, user_data_key)
        return crypto.load_ec_private_key(decrypted)
    
    def _prepare_transfer_data(self,
                               pre_transfer: PreTransferResponse,
                               user_data_key: bytes,
                               user_rsa_private_key: Optional[Any],
                               user_ecc_private_key: Optional[Any],
                               target_keys: keeper_auth.UserKeys,
                               from_username: str) -> Dict:

        transfer_data = {}
        
        key_processors = [
            ('record_keys', self._reencrypt_record_keys),
            ('shared_folder_keys', self._reencrypt_shared_folder_keys),
            ('team_keys', self._reencrypt_team_keys)
        ]
        
        for key_attr, processor_func in key_processors:
            keys = getattr(pre_transfer, key_attr, None)
            if keys:
                reencrypted, corrupted = processor_func(
                    keys, user_data_key, user_rsa_private_key, user_ecc_private_key, target_keys
                )
                transfer_data[key_attr] = reencrypted
                transfer_data[f'corrupted_{key_attr}'] = corrupted
        
        uf_keys, corrupted, transfer_folder = self._reencrypt_user_folder_keys(
            pre_transfer.user_folder_keys,
            user_data_key,
            user_rsa_private_key,
            user_ecc_private_key,
            target_keys,
            from_username
        )
        if uf_keys:
            transfer_data[TransferDataKeys.USER_FOLDER_KEYS.value] = uf_keys
        if corrupted:
            transfer_data[TransferDataKeys.CORRUPTED_USER_FOLDER_KEYS.value] = corrupted
        transfer_data[TransferDataKeys.USER_FOLDER_TRANSFER.value] = transfer_folder
        
        return transfer_data
    
    def _reencrypt_record_keys(self,
                               record_keys: List[Dict],
                               user_data_key: bytes,
                               user_rsa_key: Optional[Any],
                               user_ecc_key: Optional[Any],
                               target_keys: keeper_auth.UserKeys) -> Tuple[List[Dict], List[Dict]]:

        reencrypted = []
        corrupted = []
        
        for rk in record_keys:
            try:
                record_key = self._decrypt_key_by_type(
                    utils.base64_url_decode(rk['record_key']),
                    rk.get('record_key_type', 1),
                    user_data_key,
                    user_rsa_key,
                    user_ecc_key
                )
                
                encrypted_key, key_type = self._encrypt_for_target(
                    record_key, target_keys)
                
                reencrypted.append({
                    'record_uid': rk['record_uid'],
                    'record_key': utils.base64_url_encode(encrypted_key),
                    'record_key_type': key_type
                })
            except Exception as e:
                logger.debug(f"Corrupted record key {rk.get('record_uid', 'unknown')}: {e}")
                corrupted.append(rk)
        
        return reencrypted, corrupted
    
    def _reencrypt_shared_folder_keys(self,
                                      sf_keys: List[Dict],
                                      user_data_key: bytes,
                                      user_rsa_key: Optional[Any],
                                      user_ecc_key: Optional[Any],
                                      target_keys: keeper_auth.UserKeys) -> Tuple[List[Dict], List[Dict]]:

        reencrypted = []
        corrupted = []
        forbid_rsa = self.auth.auth_context.forbid_rsa
        
        for sfk in sf_keys:
            try:
                sf_key = self._decrypt_key_by_type(
                    utils.base64_url_decode(sfk['shared_folder_key']),
                    sfk.get('shared_folder_key_type', 1),
                    user_data_key,
                    user_rsa_key,
                    user_ecc_key
                )
                
                if forbid_rsa:
                    encrypted_key, key_type = self._encrypt_for_target(sf_key, target_keys)
                else:
                    if target_keys.aes:
                        encrypted_key = crypto.encrypt_aes_v1(sf_key, target_keys.aes)
                        key_type = EncryptionType.ENCRYPTED_BY_DATA_KEY.value
                    elif target_keys.rsa:
                        rsa_key = crypto.load_rsa_public_key(target_keys.rsa)
                        encrypted_key = crypto.encrypt_rsa(sf_key, rsa_key)
                        key_type = EncryptionType.ENCRYPTED_BY_PUBLIC_KEY.value
                    else:
                        raise Exception('No valid target key for shared folder')
                
                reencrypted.append({
                    'shared_folder_uid': sfk['shared_folder_uid'],
                    'shared_folder_key': utils.base64_url_encode(encrypted_key),
                    'shared_folder_key_type': key_type
                })
            except Exception as e:
                logger.debug(f"Corrupted SF key {sfk.get('shared_folder_uid', 'unknown')}: {e}")
                corrupted.append(sfk)
        
        return reencrypted, corrupted
    
    def _reencrypt_team_keys(self,
                            team_keys: List[Dict],
                            user_data_key: bytes,
                            user_rsa_key: Optional[Any],
                            user_ecc_key: Optional[Any],
                            target_keys: keeper_auth.UserKeys) -> Tuple[List[Dict], List[Dict]]:

        reencrypted = []
        corrupted = []
        forbid_rsa = self.auth.auth_context.forbid_rsa
        
        for tk in team_keys:
            try:
                team_key = self._decrypt_key_by_type(
                    utils.base64_url_decode(tk['team_key']),
                    tk.get('team_key_type', 1),
                    user_data_key,
                    user_rsa_key,
                    user_ecc_key
                )
                
                if forbid_rsa:
                    encrypted_key, key_type = self._encrypt_for_target(team_key, target_keys)
                else:
                    if target_keys.aes:
                        encrypted_key = crypto.encrypt_aes_v1(team_key, target_keys.aes)
                        key_type = EncryptionType.ENCRYPTED_BY_DATA_KEY.value
                    elif target_keys.rsa:
                        rsa_key = crypto.load_rsa_public_key(target_keys.rsa)
                        encrypted_key = crypto.encrypt_rsa(team_key, rsa_key)
                        key_type = EncryptionType.ENCRYPTED_BY_PUBLIC_KEY.value
                    else:
                        raise Exception('No valid target key for team')
                
                reencrypted.append({
                    'team_uid': tk['team_uid'],
                    'team_key': utils.base64_url_encode(encrypted_key),
                    'team_key_type': key_type
                })
            except Exception as e:
                logger.debug(f"Corrupted team key {tk.get('team_uid', 'unknown')}: {e}")
                corrupted.append(tk)
        
        return reencrypted, corrupted
    
    def _reencrypt_user_folder_keys(self,
                                   uf_keys: List[Dict],
                                   user_data_key: bytes,
                                   user_rsa_key: Optional[Any],
                                   user_ecc_key: Optional[Any],
                                   target_keys: keeper_auth.UserKeys,
                                   from_username: str) -> Tuple[List[Dict], List[Dict], Dict]:

        reencrypted = []
        corrupted = []
        forbid_rsa = self.auth.auth_context.forbid_rsa
        
        folder_key = utils.generate_aes_key()
        folder_name = f'Transfer from {from_username}'
        folder_data = json.dumps({'name': folder_name}).encode('utf-8')
        folder_data = crypto.encrypt_aes_v1(folder_data, folder_key)
        
        if forbid_rsa:
            if target_keys.aes:
                encrypted_folder_key = crypto.encrypt_aes_v2(folder_key, target_keys.aes)
                folder_key_type = EncryptionType.ENCRYPTED_BY_DATA_KEY_GCM.value
            elif target_keys.ec:
                ec_key = crypto.load_ec_public_key(target_keys.ec)
                encrypted_folder_key = crypto.encrypt_ec(folder_key, ec_key)
                folder_key_type = EncryptionType.ENCRYPTED_BY_PUBLIC_KEY_ECC.value
            else:
                raise Exception('No valid target key for transfer folder')
        else:
            if target_keys.aes:
                encrypted_folder_key = crypto.encrypt_aes_v1(folder_key, target_keys.aes)
                folder_key_type = EncryptionType.ENCRYPTED_BY_DATA_KEY.value
            elif target_keys.rsa:
                rsa_key = crypto.load_rsa_public_key(target_keys.rsa)
                encrypted_folder_key = crypto.encrypt_rsa(folder_key, rsa_key)
                folder_key_type = EncryptionType.ENCRYPTED_BY_PUBLIC_KEY.value
            else:
                raise Exception('No valid target key for transfer folder')
        
        transfer_folder = {
            'transfer_folder_uid': utils.generate_uid(),
            'transfer_folder_key': utils.base64_url_encode(encrypted_folder_key),
            'transfer_folder_key_type': folder_key_type,
            'transfer_folder_data': utils.base64_url_encode(folder_data)
        }
        
        for ufk in uf_keys:
            try:
                uf_key = self._decrypt_key_by_type(
                    utils.base64_url_decode(ufk['user_folder_key']),
                    ufk.get('user_folder_key_type', 1),
                    user_data_key,
                    user_rsa_key,
                    user_ecc_key
                )
                
                if forbid_rsa:
                    encrypted_key, key_type = self._encrypt_for_target(uf_key, target_keys)
                else:
                    if target_keys.aes:
                        encrypted_key = crypto.encrypt_aes_v1(uf_key, target_keys.aes)
                        key_type = EncryptionType.ENCRYPTED_BY_DATA_KEY.value
                    elif target_keys.rsa:
                        rsa_key = crypto.load_rsa_public_key(target_keys.rsa)
                        encrypted_key = crypto.encrypt_rsa(uf_key, rsa_key)
                        key_type = EncryptionType.ENCRYPTED_BY_PUBLIC_KEY.value
                    else:
                        raise Exception('No valid target key for user folder')
                
                reencrypted.append({
                    'user_folder_uid': ufk['user_folder_uid'],
                    'user_folder_key': utils.base64_url_encode(encrypted_key),
                    'user_folder_key_type': key_type
                })
            except Exception as e:
                logger.debug(f"Corrupted UF key {ufk.get('user_folder_uid', 'unknown')}: {e}")
                corrupted.append(ufk)
        
        return reencrypted, corrupted, transfer_folder
    
    def _decrypt_key_by_type(self,
                            encrypted_key: bytes,
                            key_type: int,
                            user_data_key: bytes,
                            user_rsa_key: Optional[Any],
                            user_ecc_key: Optional[Any]) -> bytes:

        if key_type == TransferKeyType.RAW_DATA_KEY.value:
            return user_data_key
        elif key_type == TransferKeyType.ENCRYPTED_BY_DATA_KEY.value:
            return crypto.decrypt_aes_v1(encrypted_key, user_data_key)
        elif key_type == TransferKeyType.ENCRYPTED_BY_RSA.value:
            if not user_rsa_key:
                raise Exception('RSA private key required but not available')
            return crypto.decrypt_rsa(encrypted_key, user_rsa_key)
        elif key_type == TransferKeyType.ENCRYPTED_BY_DATA_KEY_GCM.value:
            return crypto.decrypt_aes_v2(encrypted_key, user_data_key)
        elif key_type == TransferKeyType.ENCRYPTED_BY_ECC.value:
            if not user_ecc_key:
                raise Exception('ECC private key required but not available')
            return crypto.decrypt_ec(encrypted_key, user_ecc_key)
        else:
            raise Exception(f'Unsupported key type: {key_type}')
    
    def _encrypt_for_target(self,
                           key: bytes,
                           target_keys: keeper_auth.UserKeys) -> Tuple[bytes, str]:

        if target_keys.aes:
            return (crypto.encrypt_aes_v2(key, target_keys.aes),
                   EncryptionType.ENCRYPTED_BY_DATA_KEY_GCM.value)
        elif target_keys.ec:
            ec_key = crypto.load_ec_public_key(target_keys.ec)
            return (crypto.encrypt_ec(key, ec_key),
                   EncryptionType.ENCRYPTED_BY_PUBLIC_KEY_ECC.value)
        elif target_keys.rsa and not self.auth.auth_context.forbid_rsa:
            rsa_key = crypto.load_rsa_public_key(target_keys.rsa)
            return (crypto.encrypt_rsa(key, rsa_key),
                   EncryptionType.ENCRYPTED_BY_PUBLIC_KEY.value)
        else:
            raise Exception('No valid target public key available')
    
    def _execute_transfer(self,
                         from_username: str,
                         to_username: str,
                         transfer_data: Dict) -> TransferResult:
                         
        rq = {
            'command': 'transfer_and_delete_user',
            'from_user': from_username,
            'to_user': to_username
        }
        
        transfer_keys = [key.value for key in TransferDataKeys]
        for key in transfer_keys:
            if key in transfer_data:
                rq[key] = transfer_data[key]
        
        logger.info(f'Executing transfer_and_delete_user API: from={from_username} to={to_username}')
        if 'user_folder_transfer' in transfer_data:
            folder_transfer = transfer_data['user_folder_transfer']
            logger.info(f'Creating transfer folder: {folder_transfer.get("transfer_folder_uid", "unknown_uid")}')
        
        self.auth.execute_auth_command(rq)
        
        return TransferResult(
            success=True,
            username=from_username,
            records_transferred=len(transfer_data.get('record_keys', [])),
            shared_folders_transferred=len(transfer_data.get('shared_folder_keys', [])),
            teams_transferred=len(transfer_data.get('team_keys', [])),
            user_folders_transferred=len(transfer_data.get('user_folder_keys', [])),
            corrupted_records=len(transfer_data.get('corrupted_record_keys', [])),
            corrupted_shared_folders=len(transfer_data.get('corrupted_shared_folder_keys', [])),
            corrupted_teams=len(transfer_data.get('corrupted_team_keys', [])),
            corrupted_user_folders=len(transfer_data.get('corrupted_user_folder_keys', []))
        )

