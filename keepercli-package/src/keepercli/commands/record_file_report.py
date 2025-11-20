import argparse
from typing import Dict, List, Any, Optional

from keepersdk.vault import attachment, vault_record, record_facades
from keepersdk.authentication import endpoint
import requests

from . import base
from .. import api
from ..helpers import report_utils
from ..params import KeeperParams


logger = api.get_logger()


class RecordFileReportCommand(base.ArgparseCommand):
    """Command to generate a report of records with file attachments."""
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='file-report',
            parents=[base.report_output_parser],
            description='List records with file attachments.'
        )
        RecordFileReportCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            '-d', '--try-download', 
            dest='try_download', 
            action='store_true',
            help='Try downloading every attachment you have access to.'
        )

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        if not context.vault:
            raise ValueError("Vault is not initialized.")
        
        try_download = kwargs.get('try_download', False)
        headers = self._build_headers(try_download, kwargs.get('format'))
        table = self._build_file_report_table(context.vault, try_download)
        
        return report_utils.dump_report_data(
            table, 
            headers, 
            fmt=kwargs.get('format'), 
            filename=kwargs.get('output')
        )

    def _build_headers(self, try_download: bool, format_type: Optional[str]) -> List[str]:
        """Build headers for the report based on options."""
        headers = ['title', 'record_uid', 'record_type', 'file_id', 'file_name', 'file_size']
        
        if try_download:
            headers.append('downloadable')
        
        if format_type != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        
        return headers

    def _build_file_report_table(self, vault, try_download: bool) -> List[List[Any]]:
        """Build the main report table with file attachment data."""
        table = []
        facade = record_facades.FileRefRecordFacade()
        
        for record_uid in vault.vault_data._records:
            record = vault.vault_data.load_record(record_uid)
            
            if not self._record_has_files(record, facade):
                continue
            
            # Test download accessibility if requested
            download_statuses = {}
            if try_download:
                download_statuses = self._test_download_accessibility(vault, record_uid, record.title)
            
            # Add rows for this record's files
            table.extend(self._add_record_file_rows(record, facade, download_statuses, vault))
        
        return table

    def _record_has_files(self, record, facade) -> bool:
        """Check if a record has file attachments or file references."""
        if isinstance(record, vault_record.PasswordRecord):
            return bool(record.attachments)
        elif isinstance(record, vault_record.TypedRecord):
            facade.record = record
            return bool(facade.file_ref)
        return False

    def _test_download_accessibility(self, vault, record_uid: str, record_title: str) -> Dict[str, str]:
        """Test download accessibility for all attachments in a record."""
        logger.info('Testing download accessibility for record: %s', record_title)
        statuses = {}
        
        try:
            downloads = list(attachment.prepare_attachment_download(vault, record_uid))
            for download in downloads:
                status = self._test_single_download(download)
                if status:
                    statuses[download.file_id] = status
        except Exception as e:
            logger.debug('Error preparing downloads for record %s: %s', record_uid, e)
        
        return statuses

    def _test_single_download(self, download) -> Optional[str]:
        """Test download accessibility for a single attachment."""
        if not download.url:
            return None
        
        try:
            response = requests.get(
                download.url, 
                proxies=endpoint.get_proxies(),
                headers={"Range": "bytes=0-1"}
            )
            return 'OK' if response.status_code in {200, 206} else str(response.status_code)
        except Exception as e:
            logger.debug('Download test failed for file %s: %s', download.file_id, e)
            return None

    def _add_record_file_rows(self, record, facade, download_statuses: Dict[str, str], vault) -> List[List[Any]]:
        """Add file rows for a specific record."""
        rows = []
        
        if isinstance(record, vault_record.PasswordRecord):
            rows.extend(self._add_password_record_rows(record, download_statuses))
        elif isinstance(record, vault_record.TypedRecord):
            rows.extend(self._add_typed_record_rows(record, facade, download_statuses, vault))
        
        return rows

    def _add_password_record_rows(self, record: vault_record.PasswordRecord, download_statuses: Dict[str, str]) -> List[List[Any]]:
        """Add rows for password record attachments."""
        rows = []
        
        for attachment in record.attachments:
            row = [
                record.title,
                record.record_uid,
                '',  # No record type for password records
                attachment.id,
                attachment.title or attachment.name,
                attachment.size
            ]
            
            if download_statuses:
                row.append(download_statuses.get(attachment.id))
            
            rows.append(row)
        
        return rows

    def _add_typed_record_rows(self, record: vault_record.TypedRecord, facade, download_statuses: Dict[str, str], vault) -> List[List[Any]]:
        """Add rows for typed record file references."""
        rows = []
        facade.record = record
        
        for file_uid in facade.file_ref:
            file_record = vault.vault_data.load_record(file_uid)
            
            if isinstance(file_record, vault_record.FileRecord):
                row = [
                    record.title,
                    record.record_uid,
                    record.record_type,
                    file_record.record_uid,
                    file_record.title or file_record.file_name,
                    file_record.size
                ]
                
                if download_statuses:
                    row.append(download_statuses.get(file_record.record_uid))
                
                rows.append(row)
        
        return rows
