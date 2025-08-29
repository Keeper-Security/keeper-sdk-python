import argparse
import base64
import getpass
import json
from typing import Any, Optional, Set

from keepersdk.proto import breachwatch_pb2, client_pb2
from keepersdk.vault import vault_online, vault_record
from keepersdk import crypto, utils

from . import base
from .. import api
from ..helpers import report_utils, record_utils
from ..params import KeeperParams

logger = api.get_logger()
   
STATUS_TO_TEXT: dict[int, str] = { 
    client_pb2.BWStatus.GOOD: "GOOD", 
    client_pb2.BWStatus.WEAK: "WEAK", 
    client_pb2.BWStatus.BREACHED: "BREACHED" 
    }

UPDATE_BW_RECORD_URL = 'breachwatch/update_record_data'

class BreachWatchCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('BreachWatch.')
        self.register_command(BreachWatchListCommand(), 'list', 'l')
        self.register_command(BreachWatchIgnoreCommand(), 'ignore')
        self.register_command(BreachWatchScanCommand(), 'scan')
        self.register_command(BreachWatchPasswordCommand(), 'password')

class BreachWatchListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='breachwatch list', description='Displays a list of breached passwords.')
        parser.add_argument('--all', '-a', dest='all', action='store_true',
                            help='Display all breached records (default is to show only first 30 records)')
        parser.add_argument('--owned', '-o', dest='owned', action='store_true',
                            help='Display only breached records owned by user (omits records shared to user)')
        parser.add_argument('--numbered', '-n', action='store_true',
                            help='Display records as a numbered list')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.vault
        logger = api.get_logger()
        owned_only = kwargs.get('owned') is True
        record_uids = {x.record_uid for x in context.vault.vault_data.breach_watch_records() if x.status in (client_pb2.BWStatus.WEAK, client_pb2.BWStatus.BREACHED)}
        records = [x for x in context.vault.vault_data.records() if x.record_uid in record_uids and (x.flags & vault_record.RecordFlags.IsOwner if owned_only else True)]
        table = [[x.record_uid, x.title, x.description] for x in records]
        if table:
            table.sort(key=lambda x: x[1].casefold())
            total = len(table)
            if not kwargs.get('all', False) and total > 32:
                table = table[:30]
            columns = ['Record UID', 'Title', 'Description']
            report_utils.dump_report_data(table, columns, title='Detected High-Risk Password(s)', row_number=kwargs.get('numbered') is True)
            if len(table) < total:
                logger.info('')
                logger.info('%d records skipped.', total - len(table))
        else:
            logger.info('No breached records detected')
        scanned_record_uids = {x.record_uid for x in context.vault.vault_data.breach_watch_records()}
        not_scanned_records = [x.record_uid for x in context.vault.vault_data.records() if x.flags & vault_record.RecordFlags.IsOwner and x.record_uid not in scanned_record_uids]
        has_records_to_scan = False
        for record_uid in not_scanned_records:
            r = context.vault.vault_data.load_record(record_uid)
            if r:
                password = r.extract_password()
                if password:
                    has_records_to_scan = True
                    break
        if has_records_to_scan:
            logger.info('Some passwords in your vault has not been scanned.\n'
                        'Use "breachwatch scan" command to scan your passwords against our database '
                        'of breached accounts on the Dark Web.')


class BreachWatchIgnoreCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='breachwatch ignore', description='Ignores breached passwords.')
        parser.add_argument('records', type=str, nargs='+', help='Record UID to ignore')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        assert context.vault
        vault = context.vault

        # Parse and resolve record names to UIDs
        record_names = self._get_record_names(kwargs)
        if not record_names:
            raise base.CommandError('Record name or UID is required. Example: breachwatch ignore <RECORD_UID>')
        
        record_uids = self._resolve_record_uids(record_names, context)
        if not record_uids:
            raise base.CommandError('Record not found for the given UID/name/path')

        # Get breached records and their passwords
        breached_records = self._get_breached_records(vault)
        
        # Create breach watch requests
        bw_requests = self._create_breach_watch_requests(vault, breached_records, record_uids)
        
        # Process the requests
        if bw_requests:
            self._process_breach_watch_requests(vault, bw_requests)
            vault.sync_down(force=True)
        else:
            logger.info("No breach watch requests to process")

    def _get_record_names(self, kwargs: dict) -> list[str]:
        """Extract record names from kwargs."""
        records = kwargs.get('records')
        if not records:
            return []
        
        if isinstance(records, str):
            return [records]
        
        return records

    def _resolve_record_uids(self, record_names: list[str], context: KeeperParams) -> Set[str]:
        """Resolve record names to UIDs using the context."""
        record_uids: Set[str] = set()
        for record_name in record_names:
            record_uids.update(record_utils.resolve_records(record_name, context))
        return record_uids

    def _get_breached_records(self, vault: vault_online.VaultOnline) -> dict[str, str]:
        """Get breached records and their passwords."""
        record_passwords = {}
        
        for record in vault.vault_data.breach_watch_records():
            if record.status in (client_pb2.BWStatus.WEAK, client_pb2.BWStatus.BREACHED):
                password = self._extract_record_password(vault, record.record_uid)
                if password:
                    record_passwords[record.record_uid] = password
        
        return record_passwords

    def _extract_record_password(self, vault: vault_online.VaultOnline, record_uid: str) -> Optional[str]:
        """Extract password from a record."""
        try:
            record_data = vault.vault_data.load_record(record_uid)
            if isinstance(record_data, vault_record.PasswordRecord):
                return record_data.password
            elif isinstance(record_data, vault_record.TypedRecord):
                return record_data.extract_password()
        except Exception as e:
            logger.debug(f'Error extracting password from record {record_uid}: {e}')
        
        return None

    def _create_breach_watch_requests(self, vault: vault_online.VaultOnline, record_passwords: dict[str, str], record_uids: Set[str]) -> list[breachwatch_pb2.BreachWatchRecordRequest]:
        """Create breach watch record requests for the given records."""
        bw_requests = []
        
        for uid in record_uids:
            password = record_passwords.get(uid)
            if not password:
                continue
            
            try:
                bwrq = self._create_single_breach_watch_request(vault, uid, password)
                if bwrq:
                    bw_requests.append(bwrq)
            except Exception as e:
                logger.warning(f'Failed to create breach watch request for record {uid}: {e}')
                continue
        
        return bw_requests

    def _create_single_breach_watch_request(self, vault: vault_online.VaultOnline, record_uid: str, password: str) -> Optional[breachwatch_pb2.BreachWatchRecordRequest]:
        """Create a single breach watch record request."""
        # Create the main request
        bwrq = breachwatch_pb2.BreachWatchRecordRequest()
        bwrq.recordUid = utils.base64_url_decode(record_uid)
        bwrq.breachWatchInfoType = breachwatch_pb2.RECORD
        bwrq.updateUserWhoScanned = False

        # Create the password object
        bw_password = self._create_breach_watch_password(password)
        
        # Get existing breach watch data if available
        euid = self._get_existing_breach_watch_euid(vault, record_uid, password)
        if euid:
            bw_password.euid = euid

        # Create and encrypt the data
        bw_data = client_pb2.BreachWatchData()
        bw_data.passwords.append(bw_password)
        data = bw_data.SerializeToString()
        
        try:
            record_key = vault.vault_data.get_record_key(record_uid=record_uid)
            bwrq.encryptedData = crypto.encrypt_aes_v2(data, record_key)
            return bwrq
        except Exception as e:
            logger.warning(f'Record UID "{record_uid}" encryption error: {e}. Skipping.')
            return None

    def _create_breach_watch_password(self, password: str) -> client_pb2.BWPassword:
        """Create a breach watch password object."""
        bw_password = client_pb2.BWPassword()
        bw_password.value = password
        bw_password.resolved = utils.current_milli_time()
        bw_password.status = client_pb2.BWStatus.IGNORE
        return bw_password

    def _get_existing_breach_watch_euid(self, vault: vault_online.VaultOnline, record_uid: str, password: str) -> Optional[bytes]:
        """Get existing breach watch EUID if available."""
        bw_record = vault.vault_data.storage.breach_watch_records.get_entity(record_uid)
        if not bw_record:
            return None
        
        try:
            record_key = vault.vault_data.get_record_key(record_uid=record_uid)
            data = crypto.decrypt_aes_v2(bw_record.data, record_key)
            data_obj = json.loads(data.decode())
        except Exception as e:
            logger.debug(f'BreachWatch data record "{record_uid}" decrypt error: {e}')
            return None

        if data_obj and 'passwords' in data_obj:
            existing_password = next((x for x in data_obj['passwords'] if x.get('value', '') == password), None)
            if existing_password:
                return next((base64.b64decode(x['euid']) for x in data_obj['passwords'] if 'euid' in x), None)
        
        return None

    def _process_breach_watch_requests(self, vault: vault_online.VaultOnline, bw_requests: list[breachwatch_pb2.BreachWatchRecordRequest]) -> None:
        """Process the breach watch requests."""
        # Queue audit event
        self._queue_audit_event(vault)
        
        self._send_breach_watch_requests(vault, bw_requests)

    def _queue_audit_event(self, vault: vault_online.VaultOnline) -> None:
        """Queue audit event for the ignore action."""
        audit_plugin = vault.client_audit_event_plugin()
        if audit_plugin:
            audit_plugin.schedule_audit_event('bw_record_ignored')

    def _send_breach_watch_requests(self, vault: vault_online.VaultOnline, bw_requests: list[breachwatch_pb2.BreachWatchRecordRequest]) -> None:
        """Send breach watch requests in chunks."""
        while bw_requests:
            chunk = bw_requests[0:999]
            bw_requests = bw_requests[999:]
            
            try:
                response = self._send_breach_watch_chunk(vault, chunk)
                self._log_breach_watch_response(response)
            except Exception as e:
                logger.error(f'Error sending breach watch chunk: {e}')

    def _send_breach_watch_chunk(self, vault: vault_online.VaultOnline, chunk: list[breachwatch_pb2.BreachWatchRecordRequest]) -> breachwatch_pb2.BreachWatchUpdateResponse:
        """Send a chunk of breach watch requests."""
        rq = breachwatch_pb2.BreachWatchUpdateRequest()
        rq.breachWatchRecordRequest.extend(chunk)
        
        return vault.keeper_auth.execute_auth_rest(
            rest_endpoint=UPDATE_BW_RECORD_URL, 
            request=rq, 
            response_type=breachwatch_pb2.BreachWatchUpdateResponse
        )

    def _log_breach_watch_response(self, response: breachwatch_pb2.BreachWatchUpdateResponse) -> None:
        """Log the breach watch response."""
        for status in response.breachWatchRecordStatus:
            record_uid = utils.base64_url_encode(status.recordUid)
            logger.info(f'{record_uid}: {status.status} {status.reason}')


class BreachWatchScanCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='breachwatch scan', description='Scan for breached passwords.'
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--records', '-r', dest='records', type=str,
                            help='UID of the record to scan')

    def execute(self, context: KeeperParams, **kwargs):
        """Main execution method for breach watch scanning."""
        self._validate_context(context)
        record_uids = self._get_and_validate_record_uids(kwargs)
        
        for record_uid in record_uids:
            self._scan_single_record(context.vault, record_uid)

    def _validate_context(self, context: KeeperParams) -> None:
        """Validate that the context has required components."""
        if not context.vault:
            raise ValueError("Vault is not initialized.")
        
        if not context.auth.auth_context.license.get('breachWatchEnabled'):
            raise ValueError("Breach watch is not enabled. Please contact your administrator to enable this feature.")

    def _get_and_validate_record_uids(self, kwargs: dict) -> list[str]:
        """Extract and validate record UIDs from kwargs."""
        record_uids = kwargs.get('records')
        if not record_uids:
            raise ValueError("Record UID is required. Use -r or --records to specify the record UID. Example: 'breachwatch scan -r 1234567890'")
        
        if isinstance(record_uids, str):
            record_uids = [record_uids]
        
        return record_uids

    def _scan_single_record(self, vault: vault_online.VaultOnline, record_uid: str) -> None:
        """Scan a single record for breached passwords."""
        # Load the record
        record = self._load_record(vault, record_uid)
        if not record:
            return

        # Extract password
        password = self._extract_password(record, record_uid)
        if not password:
            return

        # Get record key for encryption
        record_key = self._get_record_key(vault, record_uid)
        if not record_key:
            return
        
        # Perform the breach watch scan
        self._perform_breach_watch_scan(vault, record_uid, record_key, password)

    def _load_record(self, vault: vault_online.VaultOnline, record_uid: str):
        """Load a record from the vault."""
        record = vault.vault_data.load_record(record_uid)
        if not record:
            logger.warning(f"Record not found: {record_uid}")
            return None
        return record

    def _extract_password(self, record: vault_record.PasswordRecord | vault_record.TypedRecord, record_uid: str) -> str:
        """Extract password from a record."""
        password = record.extract_password()
        if not password:
            logger.warning(f"Password not found in record: {record_uid}")
            return None
        return password

    def _get_record_key(self, vault: vault_online.VaultOnline, record_uid: str):
        """Get the record key for encryption/decryption."""
        record_key = vault.vault_data.get_record_key(record_uid)
        if not record_key:
            logger.warning(f"Record key not found for record: {record_uid}")
            return None
        return record_key

    def _perform_breach_watch_scan(self, vault: vault_online.VaultOnline, record_uid: str, record_key: bytes, password: str) -> None:
        """Perform the actual breach watch scan for a record."""
        try:
            bw_password = vault.breach_watch_plugin().scan_and_store_record_status(
                record_uid=record_uid,
                record_key=record_key,
                password=password
            )
            
            if bw_password:
                status = self._get_status_display(bw_password.status)
                logger.info(f"Scan completed for record {record_uid}. Status: {status}")
            else:
                logger.warning(f"Scan failed for record {record_uid}")
                
        except Exception as e:
            logger.error(f"Error scanning record {record_uid}: {str(e)}")

    def _get_status_display(self, status: int) -> str: 
        return STATUS_TO_TEXT.get(status, "UNKNOWN")


class BreachWatchPasswordCommand(base.ArgparseCommand):

    PASSWORD_FIELD_WIDTH = 16
    
    def __init__(self):
        parser = argparse.ArgumentParser(prog='breachwatch password', description='Scan a password against the breach watch database.')
        parser.add_argument('passwords', type=str, nargs='*', help='Password')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        if not self._is_vault_ready(context):
            return
            
        breach_watch = context.vault.breach_watch_plugin().breach_watch
        passwords = self._get_passwords_to_scan(kwargs)
        
        if not passwords:
            raise base.CommandError('No passwords to scan.')
            
        try:
            scan_results = self._scan_passwords(breach_watch, passwords)
            self._display_results(scan_results, kwargs.get('passwords'))
            self._cleanup_scan_data(breach_watch, scan_results)
        except Exception as e:
            logger.error(f"Error scanning passwords: {e}")

    def _is_vault_ready(self, context: KeeperParams) -> bool:
        """Check if vault and breach watch are properly initialized."""
        if not context.vault:
            raise base.CommandError('Vault is not initialized.')
        if not context.vault.breach_watch_plugin():
            raise base.CommandError('Breach watch is not enabled. Please contact your administrator to enable this feature.')
        return True

    def _get_passwords_to_scan(self, kwargs: dict) -> list[str]:
        """Get passwords from command line arguments or prompt user."""
        passwords = kwargs.get('passwords', [])
        if passwords:
            return passwords
            
        try:
            password = getpass.getpass(prompt='Password to Check: ', stream=None)
            if password.strip():
                return [password]
        except KeyboardInterrupt:
            logger.info('')
        return []

    def _scan_passwords(self, breach_watch, passwords: list[str]) -> list:
        """Scan passwords and return results with EUIDs for cleanup."""
        scan_results = []
        for result in breach_watch.scan_passwords(passwords):
            if self._is_valid_scan_result(result):
                scan_results.append(result)
        return scan_results

    def _is_valid_scan_result(self, result) -> bool:
        """Validate scan result structure."""
        return result and len(result) == 2

    def _display_results(self, scan_results: list, echo_passwords: bool) -> None:
        """Display scan results in a formatted way."""
        for result in scan_results:
            password, scan_result = result
            self._display_single_result(password, scan_result, echo_passwords)

    def _display_single_result(self, password: str, scan_result, echo_passwords: bool) -> None:
        """Display a single password scan result."""
        pwd = password if echo_passwords else "*" * len(password)
        status = self._get_status_text(scan_result)
        logger.info(f'{pwd:>{self.PASSWORD_FIELD_WIDTH}s}: {status}')

    def _get_status_text(self, scan_result) -> str:
        """Get human-readable status text for scan result."""
        is_breached = getattr(scan_result, 'breachDetected', False)
        status_code = client_pb2.BWStatus.BREACHED if is_breached else client_pb2.BWStatus.GOOD
        return STATUS_TO_TEXT.get(status_code, "Unknown")

    def _cleanup_scan_data(self, breach_watch, scan_results: list) -> None:
        """Clean up scan data by deleting EUIDs."""
        euids = self._extract_euids(scan_results)
        if euids:
            try:
                breach_watch.delete_euids(euids)
            except Exception as e:
                logger.warning(f"Failed to cleanup scan data: {e}")

    def _extract_euids(self, scan_results: list) -> list:
        """Extract EUIDs from scan results for cleanup."""
        euids = []
        for result in scan_results:
            password, scan_result = result
            if hasattr(scan_result, 'euid') and scan_result.euid:
                euids.append(scan_result.euid)
        return euids