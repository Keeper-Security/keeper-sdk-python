import argparse
import itertools
import json
import logging
from typing import Tuple, List, Set, Dict

from .base import ArgparseCommand, CommandError
from ..prompt_utils import user_choice
from ..helpers.report_utils import dump_report_data
from ..helpers.record_utils import get_totp_code

from keepersdk import crypto, utils
from keepersdk.proto import record_pb2, folder_pb2
from keepersdk.vault import vault_record

# Constants
V3_RECORD_KEY_LENGTH = 60
MAX_RECORDS_TO_DISPLAY = 99
RECORD_BATCH_SIZE = 999
SHARED_FOLDER_BATCH_SIZE = 990
SHARED_FOLDER_BATCH_THRESHOLD = 10
V2_RECORD_BATCH_SIZE = 99

# Command names
CMD_GET_SHARED_FOLDERS = 'get_shared_folders'
CMD_RECORD_UPDATE = 'record_update'

# API endpoints
EP_RECORDS_CONVERT3 = 'vault/records_convert3'
EP_SHARED_FOLDER_UPDATE_V3 = 'vault/shared_folder_update_v3'
EP_RECORDS_UPDATE = 'vault/records_update'

# Field types
FIELD_PAYMENT_CARD = 'paymentCard'
FIELD_DATE = 'date'
FIELD_ONE_TIME_CODE = 'oneTimeCode'
FIELD_UNKNOWN_TYPE = 'unknownType'

# Record types
RECORD_TYPE_LOGIN = 'login'

# Response keys
KEY_SHARED_FOLDERS = 'shared_folders'
KEY_RECORDS = 'records'
KEY_RECORD_KEY = 'record_key'
KEY_RECORD_UID = 'record_uid'
KEY_SHARED_FOLDER_UID = 'shared_folder_uid'
KEY_UPDATE_RECORDS = 'update_records'

verify_shared_folders_parser = argparse.ArgumentParser(prog='verify-shared-folders', description='Verify and fix shared folder record key issues')
verify_shared_folders_parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                                          help='Display the found problems without fixing')
verify_shared_folders_parser.add_argument('target', nargs='*', help='Shared folder UID or name.')


class VerifySharedFoldersCommand(ArgparseCommand):
    def __init__(self):
        super().__init__(verify_shared_folders_parser)

    def execute(self, params, **kwargs):
        self._validate_auth_and_vault(params)
        shared_folders = self._resolve_target_shared_folders(params, kwargs.get('target'))
        
        sf_data = self._get_shared_folders_data(params, shared_folders)
        sf_v3_keys, sf_v2_keys = self._identify_problematic_keys(params, sf_data, shared_folders)
        
        if not sf_v3_keys and not sf_v2_keys:
            if kwargs.get('dry_run'):
                print('There are no record keys to be corrected')
            return

        self._display_problematic_records(params, sf_v3_keys, sf_v2_keys)
        
        if kwargs.get('dry_run'):
            return
            
        if user_choice('Do you want to proceed?', 'yn', 'n').lower() == 'y':
            self._fix_v3_record_keys(params, sf_v3_keys)
            self._fix_v2_record_keys(params, sf_v2_keys)
            params.vault.sync_requested = True

    def _validate_auth_and_vault(self, params):
        if not params.vault:
            raise CommandError("Vault is not initialized")
        if not params.auth:
            raise CommandError("Authentication is required")

    def _resolve_target_shared_folders(self, params, target) -> Set[str]:
        shared_folders = set()
        all_shared_folders = {sf.shared_folder_uid: sf for sf in params.vault.vault_data.shared_folders()}
        
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

    def _get_shared_folders_data(self, params, shared_folders):
        rq = {
            'command': CMD_GET_SHARED_FOLDERS,
            KEY_SHARED_FOLDERS: [{KEY_SHARED_FOLDER_UID: x} for x in shared_folders],
            'include': ['sfheaders', 'sfusers', 'sfrecords']
        }
        return params.auth.execute_auth_command(rq)

    def _identify_problematic_keys(self, params, sf_data, shared_folders) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
        sf_v3_keys = []
        sf_v2_keys = []

        if KEY_SHARED_FOLDERS in sf_data:
            for sf in sf_data[KEY_SHARED_FOLDERS]:
                shared_folder_uid = sf[KEY_SHARED_FOLDER_UID]
                if KEY_RECORDS in sf:
                    for rec in sf[KEY_RECORDS]:
                        record_uid = rec[KEY_RECORD_UID]
                        record_info = params.vault.vault_data.get_record(record_uid)
                        
                        if not record_info or KEY_RECORD_KEY not in rec:
                            continue

                        record_key = utils.base64_url_decode(rec[KEY_RECORD_KEY])
                        version = record_info.version
                        
                        if version == 3 and len(record_key) != V3_RECORD_KEY_LENGTH:
                            if shared_folders is None or shared_folder_uid in shared_folders:
                                sf_v3_keys.append((record_uid, shared_folder_uid))
                        elif version == 2 and len(record_key) == V3_RECORD_KEY_LENGTH:
                            if shared_folders is None or shared_folder_uid in shared_folders:
                                sf_v2_keys.append((record_uid, shared_folder_uid))

        return sf_v3_keys, sf_v2_keys

    def _display_problematic_records(self, params, sf_v3_keys, sf_v2_keys):
        for keys, version in [(sf_v3_keys, 'V3'), (sf_v2_keys, 'V2')]:
            if len(keys) > 0:
                record_uids = list({x[0] for x in keys})
                plural = "are" if len(record_uids) > 1 else "is"
                print(f'There {plural} {len(record_uids)} {version} record key(s) to be corrected')
                
                try:
                    for record_uid in record_uids[:MAX_RECORDS_TO_DISPLAY]:
                        record = params.vault.vault_data.load_record(record_uid)
                        print(f' {record_uid}  {record.title}')
                    if len(record_uids) > MAX_RECORDS_TO_DISPLAY:
                        print(f' {(len(record_uids) - MAX_RECORDS_TO_DISPLAY)} more ...')
                except Exception:
                    pass

    def _fix_v3_record_keys(self, params, sf_v3_keys):
        if not sf_v3_keys:
            return
            
        sf_v3_keys.sort(key=lambda x: x[0])
        
        while sf_v3_keys:
            chunk = sf_v3_keys[:RECORD_BATCH_SIZE]
            sf_v3_keys = sf_v3_keys[RECORD_BATCH_SIZE:]
            self._process_v3_chunk(params, chunk)

    def _process_v3_chunk(self, params, chunk):
        record_convert = None
        last_record_uid = ''
        rq = record_pb2.RecordsConvertToV3Request()
        
        for record_uid, shared_folder_uid in chunk:
            if (shared_folder_uid not in params.shared_folder_cache or 
                record_uid not in params.record_cache):
                continue

            if last_record_uid != record_uid:
                if record_convert:
                    rq.records.append(record_convert)
                    
                record_convert = self._create_v3_convert_request(params, record_uid)
                if not record_convert:
                    continue
                last_record_uid = record_uid

            folder_key = self._create_folder_key_for_conversion(params, record_uid, shared_folder_uid)
            if folder_key:
                record_convert.folder_key.append(folder_key)

        if record_convert:
            rq.records.append(record_convert)

        params.vault.keeper_auth.execute_auth_rest(EP_RECORDS_CONVERT3, rq, 
                                                 response_type=record_pb2.RecordsModifyResponse)

    def _create_v3_convert_request(self, params, record_uid):
        record_info = params.vault.vault_data.get_record(record_uid)
        if not record_info:
            return None
            
        record_convert = record_pb2.RecordConvertToV3()
        record_convert.record_uid = utils.base64_url_decode(record_uid)
        record_convert.client_modified_time = utils.current_milli_time()
        record_convert.revision = record_info.revision
        
        self._add_audit_data_if_available(params, record_uid, record_convert)
        return record_convert

    def _add_audit_data_if_available(self, params, record_uid, record_convert):
        auth_context = params.vault.keeper_auth.auth_context
        if (hasattr(auth_context, 'enterprise_ec_public_key') and 
            auth_context.enterprise_ec_public_key):
            
            rec = params.vault.vault_data.load_record(record_uid)
            if isinstance(rec, vault_record.TypedRecord):
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

    def _create_folder_key_for_conversion(self, params, record_uid, shared_folder_uid):
        record_key = params.vault.vault_data.get_record_key(record_uid)
        shared_folder_key = params.vault.vault_data.get_shared_folder_key(shared_folder_uid)
        
        if not record_key or not shared_folder_key:
            return None
            
        fk = record_pb2.RecordFolderForConversion()
        fk.folder_uid = utils.base64_url_decode(shared_folder_uid)
        fk.record_folder_key = crypto.encrypt_aes_v2(record_key, shared_folder_key)
        return fk

    def _fix_v2_record_keys(self, params, sf_v2_keys):
        if not sf_v2_keys:
            return
            
        sf_v2_keys.sort(key=lambda x: x[1])
        rqs = {}
        results = []
        
        self._prepare_v2_update_requests(params, sf_v2_keys, rqs)
        self._execute_v2_update_requests(params, rqs, results)
        
        if results:
            headers = ['Shared Folder UID', 'Record UID', 'Record Owner', 'Error code']
            dump_report_data(results, headers=headers, title='V2 Record key errors')

    def _prepare_v2_update_requests(self, params, sf_v2_keys, rqs):
        for record_uid, shared_folder_uid in sf_v2_keys:
            if shared_folder_uid not in rqs:
                rqs[shared_folder_uid] = []

            record_key = params.vault.vault_data.get_record_key(record_uid)
            shared_folder_key = params.vault.vault_data.get_shared_folder_key(shared_folder_uid)
            
            if not record_key or not shared_folder_key:
                continue

            sfur = folder_pb2.SharedFolderUpdateRecord()
            sfur.recordUid = utils.base64_url_decode(record_uid)
            sfur.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
            sfur.encryptedRecordKey = crypto.encrypt_aes_v1(record_key, shared_folder_key)
            sfur.canEdit = folder_pb2.BOOLEAN_FALSE
            sfur.canShare = folder_pb2.BOOLEAN_TRUE
            rqs[shared_folder_uid].append(sfur)

    def _execute_v2_update_requests(self, params, rqs, results):
        sfu_rqs = None
        left = 0
        
        while len(rqs) > 0 or sfu_rqs is not None:
            if sfu_rqs is None:
                sfu_rqs = folder_pb2.SharedFolderUpdateV3RequestV2()
                left = SHARED_FOLDER_BATCH_SIZE

            shared_folder_uid = next(iter(rqs.keys()))
            sfu_records = rqs.pop(shared_folder_uid)

            sfu_rq = folder_pb2.SharedFolderUpdateV3Request()
            sfu_rq.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
            sfu_rq.forceUpdate = True

            if len(sfu_records) < left:
                sfu_rq.sharedFolderAddRecord.extend(sfu_records)
                left -= len(sfu_records)
                if left > SHARED_FOLDER_BATCH_THRESHOLD:
                    continue
            else:
                chunk = sfu_records[:left]
                sfu_records = sfu_records[left:]
                sfu_rq.sharedFolderAddRecord.extend(chunk)
                rqs[shared_folder_uid] = sfu_records

            self._execute_single_v2_update(params, sfu_rqs, results)
            sfu_rqs = None

    def _execute_single_v2_update(self, params, sfu_rqs, results):
        try:
            sfu_rss = params.vault.keeper_auth.execute_auth_rest(
                EP_SHARED_FOLDER_UPDATE_V3, sfu_rqs, 
                response_type=folder_pb2.SharedFolderUpdateV3ResponseV2
            )
            
            for sfu_rs in sfu_rss.sharedFolderUpdateV3Response:
                shared_folder_uid = utils.base64_url_encode(sfu_rs.sharedFolderUid)
                for sfu_status in sfu_rs.sharedFolderAddRecordStatus:
                    if sfu_status.status.lower() != 'success':
                        record_uid = utils.base64_url_encode(sfu_status.recordUid)
                        results.append([shared_folder_uid, record_uid, '', sfu_status.status])
        except Exception:
            pass


class VerifyRecordsCommand(ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='verify-records', description='Verify and fix record data issues')
        super().__init__(parser)

    def execute(self, params, **kwargs):
        self._validate_auth_and_vault(params)
        
        records_v2_to_fix, records_v3_to_fix = self._analyze_all_records(params)
        
        if not records_v2_to_fix and not records_v3_to_fix:
            return
            
        total_records = len(records_v2_to_fix) + len(records_v3_to_fix)
        print(f'There are {total_records} record(s) to be corrected')
        
        if user_choice('Do you want to proceed?', 'yn', 'n').lower() == 'y':
            success, failed = self._fix_records(params, records_v2_to_fix, records_v3_to_fix)
            self._log_results(success, failed)
            
            if success > 0:
                params.vault.sync_requested = True

    def _validate_auth_and_vault(self, params):
        if not params.vault:
            raise CommandError("Vault is not initialized")
        if not params.auth:
            raise CommandError("Authentication is required")

    def _analyze_all_records(self, params) -> Tuple[Dict, Dict]:
        records_v2_to_fix = {}
        records_v3_to_fix = {}

        for record_info in params.vault.vault_data.records():
            record_uid = record_info.record_uid
            
            try:
                record = params.vault.vault_data.load_record(record_uid)
                if not record:
                    continue
            except Exception:
                continue

            version = record_info.version
            if version == 3:
                data = self._analyze_v3_record(record)
                if data:
                    records_v3_to_fix[record_uid] = data
            elif version == 2:
                data = self._analyze_v2_record(record)
                if data:
                    records_v2_to_fix[record_uid] = data

        return records_v2_to_fix, records_v3_to_fix

    def _analyze_v3_record(self, record):
        if not isinstance(record, vault_record.TypedRecord):
            return None
            
        is_broken = False
        
        is_broken |= self._fix_field_values(record)
        is_broken |= self._fix_payment_card_fields(record)
        is_broken |= self._fix_date_fields(record)
        is_broken |= self._convert_otp_fields(record)
        is_broken |= self._remove_unknown_fields(record)
        is_broken |= self._move_otp_to_fields(record)

        if is_broken:
            return self._convert_v3_record_to_data(record)
        return None

    def _fix_field_values(self, record) -> bool:
        is_broken = False
        for field in itertools.chain(record.fields, record.custom):
            if not isinstance(field.value, list):
                is_broken = True
                if field.value:
                    field.value = [field.value]
                else:
                    field.value = []
        return is_broken

    def _fix_payment_card_fields(self, record) -> bool:
        is_broken = False
        for field in itertools.chain(record.fields, record.custom):
            if field.type == FIELD_PAYMENT_CARD:
                for card in field.value:
                    if isinstance(card, dict):
                        if 'cardExpirationDate' in card:
                            exp = card['cardExpirationDate']
                            if isinstance(exp, str):
                                if exp:
                                    month, sep, year = exp.partition('/')
                                    if not month.isnumeric() or not year.isnumeric():
                                        is_broken = True
                                        card['cardExpirationDate'] = ""
                            else:
                                is_broken = True
                                card['cardExpirationDate'] = ""
                    else:
                        field.value = []
                        break
        return is_broken

    def _fix_date_fields(self, record) -> bool:
        is_broken = False
        for field in itertools.chain(record.fields, record.custom):
            if field.type == FIELD_DATE:
                orig_dates = field.value
                tested_dates = [x for x in orig_dates if isinstance(x, int)]
                if len(tested_dates) < len(orig_dates):
                    field.value = tested_dates
                    is_broken = True
        return is_broken

    def _convert_otp_fields(self, record) -> bool:
        is_broken = False
        for field in record.custom:
            if field.type != FIELD_ONE_TIME_CODE and field.value:
                if isinstance(field.value, list) and len(field.value) == 1:
                    value = field.value[0]
                    if isinstance(value, str) and value.startswith('otpauth'):
                        try:
                            code, _, _ = get_totp_code(value)
                            if code:
                                field.type = FIELD_ONE_TIME_CODE
                                is_broken = True
                        except Exception:
                            pass
        return is_broken

    def _remove_unknown_fields(self, record) -> bool:
        unknown_fields = [f for f in record.custom if f.type == FIELD_UNKNOWN_TYPE]
        if unknown_fields:
            for f in unknown_fields:
                record.custom.remove(f)
            return True
        return False

    def _move_otp_to_fields(self, record) -> bool:
        if record.record_type != RECORD_TYPE_LOGIN:
            return False
            
        fields_otp = next((x for x in record.fields if x.type == FIELD_ONE_TIME_CODE), None)
        if fields_otp and fields_otp.value:
            return False
            
        custom_otp = next((x for x in record.custom if x.type == FIELD_ONE_TIME_CODE), None)
        if not custom_otp or not custom_otp.value:
            return False
            
        if fields_otp:
            fields_otp.value = custom_otp.value
        else:
            record.fields.append(custom_otp)
            
        try:
            record.custom.remove(custom_otp)
        except Exception:
            custom_otp.value = []
            
        return True

    def _convert_v3_record_to_data(self, record):
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

    def _analyze_v2_record(self, record):
        if not isinstance(record, vault_record.PasswordRecord):
            return None
            
        is_broken = False
        data = {
            'title': record.title or '',
            'secret1': record.password or '',
            'secret2': record.login or '',
            'link': record.login_url or '',
            'notes': record.notes or ''
        }
        
        for field_name in ('title', 'secret1', 'secret2', 'link', 'notes'):
            value = data[field_name]
            if not isinstance(value, str):
                if value is None:
                    data[field_name] = ''
                else:
                    data[field_name] = str(value)
                is_broken = True

        return data if is_broken else None

    def _fix_records(self, params, records_v2_to_fix, records_v3_to_fix) -> Tuple[int, List]:
        success = 0
        failed = []
        
        success_v2, failed_v2 = self._fix_v2_records(params, records_v2_to_fix)
        success_v3, failed_v3 = self._fix_v3_records(params, records_v3_to_fix)
        
        return success_v2 + success_v3, failed_v2 + failed_v3

    def _fix_v2_records(self, params, records_v2_to_fix) -> Tuple[int, List]:
        if not records_v2_to_fix:
            return 0, []
            
        success = 0
        failed = []
        record_uids = list(records_v2_to_fix.keys())
        
        while record_uids:
            chunk = record_uids[:V2_RECORD_BATCH_SIZE]
            record_uids = record_uids[V2_RECORD_BATCH_SIZE:]
            
            chunk_success, chunk_failed = self._process_v2_chunk(params, chunk, records_v2_to_fix)
            success += chunk_success
            failed.extend(chunk_failed)
            
        return success, failed

    def _process_v2_chunk(self, params, chunk, records_v2_to_fix) -> Tuple[int, List]:
        rq = {
            'command': CMD_RECORD_UPDATE,
            'client_time': utils.current_milli_time(),
            'pt': 'Commander',
            KEY_UPDATE_RECORDS: []
        }

        for record_uid in chunk:
            record_info = params.vault.vault_data.get_record(record_uid)
            record_key = params.vault.vault_data.get_record_key(record_uid)
            
            if not record_info or not record_key:
                continue
                
            data = records_v2_to_fix[record_uid]
            encrypted_data = crypto.encrypt_aes_v1(json.dumps(data).encode(), record_key)

            rq[KEY_UPDATE_RECORDS].append({
                KEY_RECORD_UID: record_uid,
                'version': 2,
                'data': utils.base64_url_encode(encrypted_data),
                'client_modified_time': utils.current_milli_time(),
                'revision': record_info.revision,
            })

        rs = params.auth.execute_auth_command(rq)
        return self._process_v2_response(rs)

    def _process_v2_response(self, rs) -> Tuple[int, List]:
        success = 0
        failed = []
        
        for rs_status in rs.get(KEY_UPDATE_RECORDS) or []:
            record_uid = rs_status[KEY_RECORD_UID]
            status = rs_status.get('status')
            if status == 'success':
                success += 1
            else:
                failed.append(f'{record_uid}: {rs_status.get("message", status)}')
                
        return success, failed

    def _fix_v3_records(self, params, records_v3_to_fix) -> Tuple[int, List]:
        if not records_v3_to_fix:
            return 0, []
            
        rq = record_pb2.RecordsUpdateRequest()
        rq.client_time = utils.current_milli_time()
        
        for record_uid in records_v3_to_fix:
            record_info = params.vault.vault_data.get_record(record_uid)
            record_key = params.vault.vault_data.get_record_key(record_uid)
            
            if not record_info or not record_key:
                continue

            upd_rq = record_pb2.RecordUpdate()
            upd_rq.record_uid = utils.base64_url_decode(record_uid)
            upd_rq.client_modified_time = utils.current_milli_time()
            upd_rq.revision = record_info.revision
            data = records_v3_to_fix[record_uid]
            upd_rq.data = crypto.encrypt_aes_v2(json.dumps(data).encode('utf-8'), record_key)
            rq.records.append(upd_rq)

            if len(rq.records) >= RECORD_BATCH_SIZE:
                break

        rs = params.vault.keeper_auth.execute_auth_rest(EP_RECORDS_UPDATE, rq, 
                                                      response_type=record_pb2.RecordsModifyResponse)
        return self._process_v3_response(rs)

    def _process_v3_response(self, rs) -> Tuple[int, List]:
        success = 0
        failed = []
        
        for status in rs.records:
            if status.status == record_pb2.RS_SUCCESS:
                success += 1
            else:
                record_uid = utils.base64_url_encode(status.record_uid)
                failed.append(f'{record_uid}: {status.message}')
                
        return success, failed

    def _log_results(self, success, failed):
        if success > 0:
            logging.info('Successfully corrected %d record(s)', success)
        if len(failed) > 0:
            logging.warning('Failed to correct %d record(s)', len(failed))
            logging.info('\n'.join(failed))
