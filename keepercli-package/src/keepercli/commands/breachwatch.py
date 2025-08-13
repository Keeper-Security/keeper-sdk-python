import argparse
from typing import Any, Set

from keepersdk.proto import client_pb2
from keepersdk.vault import vault_record

from . import base
from .. import api
from ..helpers import report_utils, record_utils
from ..params import KeeperParams

logger = api.get_logger()

class BreachWatchCommand(base.GroupCommand):
    def __init__(self):
        super().__init__('BreachWatch.')
        self.register_command(BreachWatchListCommand(), 'list', 'l')
        self.register_command(BreachWatchIgnoreCommand(), 'ignore')
        self.register_command(BreachWatchScanCommand(), 'scan')

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

        records = kwargs.get('records')
        if not records:
            return
        if isinstance(records, str):
            records = [records]

        record_uids: Set[str] = set()
        for record_name in records:
            record_uids.update(record_utils.resolve_records(record_name, context))

        if len(record_uids) == 0:
            return
        # TODO
        """
        bw_requests: List[breachwatch_pb2.BreachWatchRecordRequest] = []
        for record, password in params.breach_watch.get_records_by_status(params, ['WEAK', 'BREACHED']):
            if record.record_uid not in record_uids:
                continue
            record_uids.remove(record.record_uid)
            bwrq = breachwatch_pb2.BreachWatchRecordRequest()
            bwrq.recordUid = utils.base64_url_decode(record.record_uid)
            bwrq.breachWatchInfoType = breachwatch_pb2.RECORD
            bwrq.updateUserWhoScanned = False

            bw_password = client_pb2.BWPassword()
            bw_password.value = password.get('value')
            bw_password.resolved = utils.current_milli_time()
            bw_password.status = client_pb2.IGNORE
            euid = password.get('euid')
            if euid:
                bw_password.euid = base64.b64decode(euid)
            bw_data = client_pb2.BreachWatchData()
            bw_data.passwords.append(bw_password)
            data = bw_data.SerializeToString()
            try:
                record_key = params.record_cache[record.record_uid]['record_key_unencrypted']
                bwrq.encryptedData = crypto.encrypt_aes_v2(data, record_key)
            except:
                logging.warning(f'Record UID "{record.record_uid}" encryption error. Skipping.')
                continue
            bw_requests.append(bwrq)

        for record_uid in record_uids:
            logging.warning(f'Record UID "{record_uid}" cannot ignore. Skipping.')

        if bw_requests:
            params.sync_data = True
            if params.breach_watch.send_audit_events:
                params.queue_audit_event('bw_record_ignored')

            while bw_requests:
                chunk = bw_requests[0:999]
                bw_requests = bw_requests[999:]
                rq = breachwatch_pb2.BreachWatchUpdateRequest()
                rq.breachWatchRecordRequest.extend(chunk)
                rs = api.communicate_rest(params, rq, 'breachwatch/update_record_data',
                                          rs_type=breachwatch_pb2.BreachWatchUpdateResponse)
                for status in rs.breachWatchRecordStatus:
                    logging.info(f'{utils.base64_url_encode(status.recordUid)}: {status.status} {status.reason}')
        """


class BreachWatchScanCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='breachwatch scan', description='Scan for breached passwords.'
        )
        self.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
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
        
        if not context.vault.breach_watch_plugin():
            raise ValueError("Breach watch is not enabled.")

    def _get_and_validate_record_uids(self, kwargs: dict) -> list:
        """Extract and validate record UIDs from kwargs."""
        record_uids = kwargs.get('records')
        if not record_uids:
            raise ValueError("Record UID is required.")
        
        if isinstance(record_uids, str):
            record_uids = [record_uids]
        
        return record_uids

    def _scan_single_record(self, vault, record_uid: str) -> None:
        """Scan a single record for breached passwords."""
        record = self._load_record(vault, record_uid)
        if not record:
            return

        password = self._extract_password(record, record_uid)
        if not password:
            return

        record_key = self._get_record_key(vault, record_uid)
        if not record_key:
            return
        
        self._perform_breach_watch_scan(vault, record_uid, record_key, password)

    def _load_record(self, vault, record_uid: str):
        """Load a record from the vault."""
        record = vault.vault_data.load_record(record_uid)
        if not record:
            logger.warning(f"Record not found: {record_uid}")
        return record

    def _extract_password(self, record, record_uid: str) -> str:
        """Extract password from a record."""
        password = record.extract_password()
        if not password:
            logger.warning(f"Password not found in record: {record_uid}")
        return password

    def _get_record_key(self, vault, record_uid: str):
        """Get the record key for encryption/decryption."""
        record_key = vault.vault_data.get_record_key(record_uid)
        if not record_key:
            logger.warning(f"Record key not found for record: {record_uid}")
        return record_key

    def _perform_breach_watch_scan(self, vault, record_uid: str, record_key, password: str) -> None:
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

    def _get_status_display(self, status) -> str:
        """Convert breach watch status to human-readable format."""
        return "WEAK" if status == client_pb2.BWStatus.WEAK or status == client_pb2.BWStatus.BREACHED else "GOOD"
                