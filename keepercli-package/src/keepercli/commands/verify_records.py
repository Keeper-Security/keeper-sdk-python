import argparse
import itertools
import json
from typing import Tuple, List, Optional, Set, Dict

from .base import ArgparseCommand, CommandError
from ..params import KeeperParams
from ..prompt_utils import user_choice
from ..helpers.report_utils import dump_report_data
from ..helpers.record_utils import get_totp_code
from .. import api
from keepersdk import crypto, utils
from keepersdk.proto import record_pb2, folder_pb2
from keepersdk.vault import vault_record, vault_online


logger = api.get_logger()


# Constants
MAX_DISPLAY_RECORDS = 99
MAX_RECORDS_CHUNK = 999
MAX_SF_CHUNK = 990
MIN_BATCH_THRESHOLD = 10
V3_RECORD_KEY_LENGTH = 60

class VerifySharedFoldersCommand(ArgparseCommand):
    def __init__(self):
        self.parser = argparse.ArgumentParser(prog='verify-shared-folders', 
                                       description='Verify and fix shared folder record key issues')
        VerifySharedFoldersCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                           help='Display the found problems without fixing')
        parser.add_argument('target', nargs='*', help='Shared folder UID or name.')

    def execute(self, context: KeeperParams, **kwargs):
        self._validate_context(context)
        vault = context.vault
        shared_folders = self._resolve_target_folders(vault, kwargs.get('target'))
        sf_v3_keys, sf_v2_keys = self._find_problematic_keys(vault, shared_folders)
        
        if not sf_v3_keys and not sf_v2_keys:
            if kwargs.get('dry_run'):
                logger.info('There are no record keys to be corrected')
            return
        
        self._display_problems(vault, sf_v3_keys, sf_v2_keys)
        
        if not kwargs.get('dry_run') and self._get_user_confirmation():
            self._fix_record_keys(vault, sf_v3_keys, sf_v2_keys)
            vault.sync_down()
    
    def _validate_context(self, context: KeeperParams) -> None:
        if not context.vault or not context.auth:
            raise CommandError("Vault is not initialized, authentication is required")
    
    def _resolve_target_folders(self, vault: vault_online.VaultOnline, target) -> Set[str]:
        shared_folders = set()
        all_shared_folders = {sf.shared_folder_uid: sf for sf in vault.vault_data.shared_folders()}
        
        if isinstance(target, list) and len(target) > 0:
            sf_names = {sf.name.lower(): sf.shared_folder_uid for sf in all_shared_folders.values()}
            for name in target:
                if name in all_shared_folders:
                    shared_folders.add(name)
                else:
                    sf_name = name.lower()
                    if sf_name in sf_names:
                        shared_folders.add(sf_names[sf_name])
                    else:
                        raise CommandError(f'Shared folder "{name}" not found')
        else:
            shared_folders.update(all_shared_folders.keys())

        if len(shared_folders) == 0:
            raise CommandError('No shared folders found')
        
        return shared_folders
    
    def _find_problematic_keys(self, vault: vault_online.VaultOnline, shared_folders) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
        rq = {
            'command': 'get_shared_folders',
            'shared_folders': [{'shared_folder_uid': x} for x in shared_folders],
            'include': ['sfheaders', 'sfusers', 'sfrecords']
        }
        rs = vault.keeper_auth.execute_auth_command(rq)

        sf_v3_keys = []
        sf_v2_keys = []

        if 'shared_folders' in rs:
            for sf in rs['shared_folders']:
                shared_folder_uid = sf['shared_folder_uid']
                if 'records' in sf:
                    for rec in sf['records']:
                        record_uid = rec['record_uid']
                        record_info = vault.vault_data.get_record(record_uid)
                        if not record_info or 'record_key' not in rec:
                            continue

                        record_key = utils.base64_url_decode(rec['record_key'])
                        version = record_info.version
                        
                        if version == 3 and len(record_key) != V3_RECORD_KEY_LENGTH:
                            sf_v3_keys.append((record_uid, shared_folder_uid))
                        elif version == 2 and len(record_key) == V3_RECORD_KEY_LENGTH:
                            sf_v2_keys.append((record_uid, shared_folder_uid))
        
        return sf_v3_keys, sf_v2_keys
    
    def _display_problems(self, vault: vault_online.VaultOnline, sf_v3_keys, sf_v2_keys):
        if sf_v3_keys:
            self._display_record_list(vault, sf_v3_keys, "V3")
        if sf_v2_keys:
            self._display_record_list(vault, sf_v2_keys, "V2")
    
    def _display_record_list(self, vault: vault_online.VaultOnline, keys, version):
        record_uids = list({x[0] for x in keys})
        plural = "are" if len(record_uids) > 1 else "is"
        logger.info(f'There {plural} {len(record_uids)} {version} record key(s) to be corrected')
        
        try:
            for record_uid in record_uids[:MAX_DISPLAY_RECORDS]:
                record = vault.vault_data.load_record(record_uid)
                logger.info(f' {record_uid}  {record.title}')
            if len(record_uids) > MAX_DISPLAY_RECORDS:
                logger.info(f' {(len(record_uids) - MAX_DISPLAY_RECORDS)} more ...')
        except Exception:
            pass
    
    def _get_user_confirmation(self) -> bool:
        answer = user_choice('Do you want to proceed?', 'yn', 'n')
        return answer.lower() == 'y'
    
    def _fix_record_keys(self, vault: vault_online.VaultOnline, sf_v3_keys, sf_v2_keys):
        if sf_v3_keys:
            self._fix_v3_keys(vault, sf_v3_keys)
        if sf_v2_keys:
            self._fix_v2_keys(vault, sf_v2_keys)
    
    def _fix_v3_keys(self, vault: vault_online.VaultOnline, sf_v3_keys):
        sf_v3_keys.sort(key=lambda x: x[0])
        while sf_v3_keys:
            chunk = sf_v3_keys[:MAX_RECORDS_CHUNK]
            sf_v3_keys = sf_v3_keys[MAX_RECORDS_CHUNK:]
            self._process_v3_chunk(vault, chunk)
    
    def _process_v3_chunk(self, vault: vault_online.VaultOnline, chunk):
        rq = record_pb2.RecordsConvertToV3Request()
        record_convert = None
        last_record_uid = ''
        
        for record_uid, shared_folder_uid in chunk:
            shared_folder_key = vault.vault_data.get_shared_folder_key(shared_folder_uid)
            record_key = vault.vault_data.get_record_key(record_uid)
            
            if not shared_folder_key or not record_key:
                continue

            if last_record_uid != record_uid:
                if record_convert:
                    rq.records.append(record_convert)
                record_convert = self._create_v3_record_convert(vault, record_uid)
                last_record_uid = record_uid
            
            self._add_folder_key_to_convert(vault, record_convert, record_uid, shared_folder_uid)

        if record_convert:
            rq.records.append(record_convert)

        vault.keeper_auth.execute_auth_rest('vault/records_convert3', rq, 
                                                  response_type=record_pb2.RecordsModifyResponse)
    
    def _create_v3_record_convert(self, vault: vault_online.VaultOnline, record_uid):
        record_info = vault.vault_data.get_record(record_uid)
        if not record_info:
            return None
            
        record_convert = record_pb2.RecordConvertToV3()
        record_convert.record_uid = utils.base64_url_decode(record_uid)
        record_convert.client_modified_time = utils.current_milli_time()
        record_convert.revision = record_info.revision
        
        self._add_audit_data(vault, record_convert, record_uid)
        return record_convert
    
    def _add_audit_data(self, vault: vault_online.VaultOnline, record_convert, record_uid):
        auth_context = vault.keeper_auth.auth_context
        if not auth_context.enterprise_ec_public_key:
            return
            
        rec = vault.vault_data.load_record(record_uid)
        if not isinstance(rec, vault_record.TypedRecord):
            return
            
        audit_data = {
            'title': rec.title or '',
            'record_type': rec.record_type,
        }
        
        field = rec.get_typed_field('url')
        if field:
            default_value = field.get_default_value(str)
            if default_value:
                audit_data['url'] = utils.url_strip(default_value)
                
        record_convert.audit.data = crypto.encrypt_ec(
            json.dumps(audit_data).encode('utf-8'), 
            auth_context.enterprise_ec_public_key
        )
    
    def _add_folder_key_to_convert(self, vault: vault_online.VaultOnline, record_convert, record_uid, shared_folder_uid):
        fk = record_pb2.RecordFolderForConversion()
        fk.folder_uid = utils.base64_url_decode(shared_folder_uid)
        
        record_key = vault.vault_data.get_record_key(record_uid)
        shared_folder_key = vault.vault_data.get_shared_folder_key(shared_folder_uid)
        
        if record_key and shared_folder_key:
            fk.record_folder_key = crypto.encrypt_aes_v2(record_key, shared_folder_key)
            record_convert.folder_key.append(fk)
    
    def _fix_v2_keys(self, vault: vault_online.VaultOnline, sf_v2_keys):
        sf_v2_keys.sort(key=lambda x: x[1])
        rqs = {}
        results = []

        for record_uid, shared_folder_uid in sf_v2_keys:
            if shared_folder_uid not in rqs:
                rqs[shared_folder_uid] = []

            record_key = vault.vault_data.get_record_key(record_uid)
            shared_folder_key = vault.vault_data.get_shared_folder_key(shared_folder_uid)
            
            if not record_key or not shared_folder_key:
                continue

            sfur = folder_pb2.SharedFolderUpdateRecord()
            sfur.recordUid = utils.base64_url_decode(record_uid)
            sfur.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
            sfur.encryptedRecordKey = crypto.encrypt_aes_v1(record_key, shared_folder_key)
            sfur.canEdit = folder_pb2.BOOLEAN_FALSE
            sfur.canShare = folder_pb2.BOOLEAN_TRUE
            rqs[shared_folder_uid].append(sfur)

        self._process_v2_updates(vault, rqs, results)
        
        if results:
            headers = ['Shared Folder UID', 'Record UID', 'Record Owner', 'Error code']
            dump_report_data(results, headers=headers, title='V2 Record key errors')
    
    def _process_v2_updates(self, vault: vault_online.VaultOnline, rqs, results):
        sfu_rqs = None
        left = 0
        
        while len(rqs) > 0 or sfu_rqs is not None:
            if sfu_rqs is None:
                sfu_rqs = folder_pb2.SharedFolderUpdateV3RequestV2()
                left = MAX_SF_CHUNK

            shared_folder_uid = next(iter(rqs.keys()))
            sfu_records = rqs.pop(shared_folder_uid)

            sfu_rq = folder_pb2.SharedFolderUpdateV3Request()
            sfu_rq.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
            sfu_rq.forceUpdate = True

            if len(sfu_records) < left:
                sfu_rq.sharedFolderAddRecord.extend(sfu_records)
                left -= len(sfu_records)
                if left > MIN_BATCH_THRESHOLD:
                    continue
            else:
                chunk = sfu_records[:left]
                sfu_records = sfu_records[left:]
                sfu_rq.sharedFolderAddRecord.extend(chunk)
                rqs[shared_folder_uid] = sfu_records

            try:
                sfu_rss = vault.keeper_auth.execute_auth_rest(
                    'vault/shared_folder_update_v3', sfu_rqs, 
                    response_type=folder_pb2.SharedFolderUpdateV3ResponseV2
                )
                
                for sfu_rs in sfu_rss.sharedFoldersUpdateV3Response:
                    shared_folder_uid = utils.base64_url_encode(sfu_rs.sharedFolderUid)
                    for sfu_status in sfu_rs.sharedFolderAddRecordStatus:
                        if sfu_status.status.lower() != 'success':
                            record_uid = utils.base64_url_encode(sfu_status.recordUid)
                            results.append([shared_folder_uid, record_uid, '', sfu_status.status])
            except Exception:
                pass
            finally:
                sfu_rqs = None


class VerifyRecordsCommand(ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='verify-records', description='Verify and fix record data issues')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        self._validate_context(context)
        vault = context.vault
        records_v3_to_fix, records_v2_to_fix = self._analyze_records(vault)
        
        if not records_v2_to_fix and not records_v3_to_fix:
            return
            
        total_records = len(records_v2_to_fix) + len(records_v3_to_fix)
        logger.info(f'There are {total_records} record(s) to be corrected')
        
        if self._get_user_confirmation():
            success, failed = self._fix_records(vault, records_v2_to_fix, records_v3_to_fix)
            self._report_results(success, failed)
            
            if success > 0:
                vault.sync_down()
    
    def _validate_context(self, context: KeeperParams) -> None:
        if not context.vault or not context.auth:
            raise CommandError("Vault is not initialized, authentication is required")
    
    def _analyze_records(self, vault: vault_online.VaultOnline) -> Tuple[Dict[str, dict], Dict[str, dict]]:
        records_v3_to_fix = {}
        records_v2_to_fix = {}

        for record_info in vault.vault_data.records():
            record_uid = record_info.record_uid
            
            try:
                record = vault.vault_data.load_record(record_uid)
                if not record:
                    continue
            except Exception:
                continue

            version = record_info.version
            if version == 3:
                fixed_data = self._analyze_v3_record(record)
                if fixed_data:
                    records_v3_to_fix[record_uid] = fixed_data
            elif version == 2:
                fixed_data = self._analyze_v2_record(record)
                if fixed_data:
                    records_v2_to_fix[record_uid] = fixed_data
            elif version > 3:
                fixed_data = self._analyze_v3_record(record)
                if fixed_data:
                    records_v3_to_fix[record_uid] = fixed_data
                    
        return records_v3_to_fix, records_v2_to_fix
    
    def _analyze_v3_record(self, record) -> Optional[dict]:
        if isinstance(record, vault_record.TypedRecord):
            return self._analyze_typed_record(record)
        elif hasattr(record, 'fields') and hasattr(record, 'custom'):
            return self._analyze_generic_v3_record(record)
        else:
            return None
    
    def _analyze_typed_record(self, record: vault_record.TypedRecord) -> Optional[dict]:
        is_broken = False
        
        for field in itertools.chain(record.fields, record.custom):
            if self._fix_field_value_format(field):
                is_broken = True
            if self._fix_payment_card_expiration(field):
                is_broken = True
            if self._fix_date_field_types(field):
                is_broken = True
        
        if self._fix_custom_otp_fields(record):
            is_broken = True
        if self._remove_unknown_type_fields(record):
            is_broken = True
        if self._move_login_otp_to_fields(record):
            is_broken = True

        return self._convert_record_to_data(record) if is_broken else None
    
    def _analyze_generic_v3_record(self, record) -> Optional[dict]:
        is_broken = False
        
        if hasattr(record, 'fields'):
            for field in record.fields:
                if hasattr(field, 'value') and not isinstance(field.value, list):
                    if field.value:
                        field.value = [field.value]
                    else:
                        field.value = []
                    is_broken = True
        
        return self._convert_generic_record_to_data(record) if is_broken else None
    
    def _convert_generic_record_to_data(self, record) -> dict:
        data = {
            'type': getattr(record, 'record_type', 'login'),
            'title': getattr(record, 'title', ''),
            'notes': getattr(record, 'notes', ''),
            'fields': [],
            'custom': []
        }
        
        if hasattr(record, 'fields'):
            for field in record.fields:
                data['fields'].append({
                    'type': getattr(field, 'type', 'text'),
                    'label': getattr(field, 'label', ''),
                    'value': getattr(field, 'value', [])
                })
        
        if hasattr(record, 'custom'):
            for field in record.custom:
                data['custom'].append({
                    'type': getattr(field, 'type', 'text'),
                    'label': getattr(field, 'label', ''),
                    'value': getattr(field, 'value', [])
                })
        
        return data
    
    def _fix_field_value_format(self, field) -> bool:
        if not isinstance(field.value, list):
            if field.value:
                field.value = [field.value]
            else:
                field.value = []
            return True
        return False
    
    def _fix_payment_card_expiration(self, field) -> bool:
        if field.type != 'paymentCard':
            return False
            
        is_broken = False
        for card in field.value:
            if isinstance(card, dict) and 'cardExpirationDate' in card:
                exp = card['cardExpirationDate']
                if isinstance(exp, str) and exp:
                    month, sep, year = exp.partition('/')
                    if not month.isnumeric() or not year.isnumeric():
                        card['cardExpirationDate'] = ""
                        is_broken = True
                elif not isinstance(exp, str):
                    card['cardExpirationDate'] = ""
                    is_broken = True
            elif not isinstance(card, dict):
                field.value = []
                is_broken = True
                break
        return is_broken
    
    def _fix_date_field_types(self, field) -> bool:
        if field.type != 'date':
            return False
            
        orig_dates = field.value
        tested_dates = [x for x in orig_dates if isinstance(x, int)]
        if len(tested_dates) < len(orig_dates):
            field.value = tested_dates
            return True
        return False
    
    def _fix_custom_otp_fields(self, record) -> bool:
        is_broken = False
        for field in record.custom:
            if (field.type != 'oneTimeCode' and field.value and 
                isinstance(field.value, list) and len(field.value) == 1):
                value = field.value[0]
                if isinstance(value, str) and value.startswith('otpauth'):
                    try:
                        code, _, _ = get_totp_code(value)
                        if code:
                            field.type = 'oneTimeCode'
                            is_broken = True
                    except Exception:
                        pass
        return is_broken
    
    def _remove_unknown_type_fields(self, record) -> bool:
        unknown_fields = [f for f in record.custom if f.type == 'unknownType']
        if unknown_fields:
            for f in unknown_fields:
                record.custom.remove(f)
            return True
        return False
    
    def _move_login_otp_to_fields(self, record) -> bool:
        if record.record_type != 'login':
            return False
            
        fields_otp = next((x for x in record.fields if x.type == 'oneTimeCode'), None)
        if fields_otp and fields_otp.value:
            return False
            
        custom_otp = next((x for x in record.custom if x.type == 'oneTimeCode'), None)
        if not custom_otp or not custom_otp.value:
            return False
            
        if fields_otp:
            fields_otp.value = custom_otp.value
        else:
            record.fields.append(custom_otp)
            
        try:
            record.custom.remove(custom_otp)
        except ValueError:
            custom_otp.value = []
            
        return True
    
    def _convert_record_to_data(self, record) -> dict:
        data = {
            'type': record.record_type,
            'title': record.title,
            'notes': record.notes,
            'fields': [],
            'custom': []
        }
        
        for field in record.fields:
            data['fields'].append({
                'type': field.type,
                'label': field.label,
                'value': field.value
            })
        
        for field in record.custom:
            data['custom'].append({
                'type': field.type,
                'label': field.label,
                'value': field.value
            })
        
        return data
    
    def _analyze_v2_record(self, record) -> Optional[dict]:
        if isinstance(record, vault_record.PasswordRecord):
            return self._analyze_password_record(record)
        elif hasattr(record, 'title'):
            return self._analyze_generic_v2_record(record)
        else:
            return None
    
    def _analyze_password_record(self, record: vault_record.PasswordRecord) -> Optional[dict]:
        is_broken = False
        data = {
            'title': record.title or '',
            'secret1': record.password or '',
            'secret2': record.login or '',
            'link': record.link or '',
            'notes': record.notes or ''
        }
        
        for field_name in ('title', 'secret1', 'secret2', 'link', 'notes'):
            value = data[field_name]
            if not isinstance(value, str):
                data[field_name] = '' if value is None else str(value)
                is_broken = True

        return data if is_broken else None
    
    def _analyze_generic_v2_record(self, record) -> Optional[dict]:
        is_broken = False
        data = {
            'title': getattr(record, 'title', '') or '',
            'secret1': getattr(record, 'password', '') or getattr(record, 'secret1', '') or '',
            'secret2': getattr(record, 'login', '') or getattr(record, 'secret2', '') or '',
            'link': getattr(record, 'login_url', '') or getattr(record, 'link', '') or '',
            'notes': getattr(record, 'notes', '') or ''
        }
        
        for field_name in ('title', 'secret1', 'secret2', 'link', 'notes'):
            value = data[field_name]
            if not isinstance(value, str):
                data[field_name] = '' if value is None else str(value)
                is_broken = True

        return data if is_broken else None
    
    def _get_user_confirmation(self) -> bool:
        answer = user_choice('Do you want to proceed?', 'yn', 'n')
        return answer.lower() == 'y'
    
    def _fix_records(self, vault: vault_online.VaultOnline, records_v2_to_fix, records_v3_to_fix) -> Tuple[int, List[str]]:
        success = 0
        failed = []

        if records_v2_to_fix:
            v2_success, v2_failed = self._fix_v2_records(vault, records_v2_to_fix)
            success += v2_success
            failed.extend(v2_failed)

        if records_v3_to_fix:
            v3_success, v3_failed = self._fix_v3_records(vault, records_v3_to_fix)
            success += v3_success
            failed.extend(v3_failed)
            
        return success, failed
    
    def _fix_v2_records(self, vault: vault_online.VaultOnline, records_v2_to_fix) -> Tuple[int, List[str]]:
        success = 0
        failed = []
        record_uids = list(records_v2_to_fix.keys())
        
        while record_uids:
            chunk = record_uids[:MAX_DISPLAY_RECORDS]
            record_uids = record_uids[MAX_DISPLAY_RECORDS:]
            chunk_success, chunk_failed = self._process_v2_chunk(vault, records_v2_to_fix, chunk)
            success += chunk_success
            failed.extend(chunk_failed)
            
        return success, failed
    
    def _process_v2_chunk(self, vault: vault_online.VaultOnline, records_v2_to_fix, chunk) -> Tuple[int, List[str]]:
        rq = {
            'command': 'record_update',
            'client_time': utils.current_milli_time(),
            'pt': 'Commander',
            'update_records': []
        }

        for record_uid in chunk:
            record_info = vault.vault_data.get_record(record_uid)
            record_key = vault.vault_data.get_record_key(record_uid)
            
            if not record_info or not record_key:
                continue
                
            data = records_v2_to_fix[record_uid]
            encrypted_data = crypto.encrypt_aes_v1(json.dumps(data).encode(), record_key)

            rq['update_records'].append({
                'record_uid': record_uid,
                'version': 2,
                'data': utils.base64_url_encode(encrypted_data),
                'client_modified_time': utils.current_milli_time(),
                'revision': record_info.revision,
            })

        rs = vault.keeper_auth.execute_auth_command(rq)
        success = 0
        failed = []
        
        for rs_status in rs.get('update_records') or []:
            record_uid = rs_status['record_uid']
            status = rs_status.get('status')
            if status == 'success':
                success += 1
            else:
                failed.append(f'{record_uid}: {rs_status.get("message", status)}')
                
        return success, failed
    
    def _fix_v3_records(self, vault: vault_online.VaultOnline, records_v3_to_fix) -> Tuple[int, List[str]]:
        rq = record_pb2.RecordsUpdateRequest()
        rq.client_time = utils.current_milli_time()
        
        for record_uid in records_v3_to_fix:
            record_info = vault.vault_data.get_record(record_uid)
            record_key = vault.vault_data.get_record_key(record_uid)
            
            if not record_info or not record_key:
                continue

            upd_rq = record_pb2.RecordUpdate()
            upd_rq.record_uid = utils.base64_url_decode(record_uid)
            upd_rq.client_modified_time = utils.current_milli_time()
            upd_rq.revision = record_info.revision
            data = records_v3_to_fix[record_uid]
            upd_rq.data = crypto.encrypt_aes_v2(json.dumps(data).encode('utf-8'), record_key)
            rq.records.append(upd_rq)

            if len(rq.records) >= MAX_RECORDS_CHUNK:
                break

        rs = vault.keeper_auth.execute_auth_rest(
            'vault/records_update', rq, response_type=record_pb2.RecordsModifyResponse
        )
        
        success = 0
        failed = []
        
        for status in rs.records:
            if status.status == record_pb2.RS_SUCCESS:
                success += 1
            else:
                record_uid = utils.base64_url_encode(status.record_uid)
                failed.append(f'{record_uid}: {status.message}')
                
        return success, failed
    
    def _report_results(self, success: int, failed: List[str]) -> None:
        if success > 0:
            logger.info('Successfully corrected %d record(s)', success)
        if failed:
            logger.warning('Failed to correct %d record(s)', len(failed))
            logger.info('\n'.join(failed))
