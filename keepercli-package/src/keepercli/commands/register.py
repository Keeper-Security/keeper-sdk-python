import argparse

from keepersdk import crypto, utils
from keepersdk.proto import APIRequest_pb2
from keepersdk.vault import vault_utils

from . import base
from .. import api
from ..helpers import report_utils, share_utils
from ..params import KeeperParams

CHUNK_SIZE = 1000
OWNERLESS_RECORDS_GET_ENDPOINT = 'ownerless_records/get_records'
OWNERLESS_RECORDS_SET_OWNER_ENDPOINT = 'ownerless_records/set_owner'
DEFAULT_OUTPUT_FORMAT = 'table'
DEFAULT_VERBOSE_THRESHOLD = 0  # When verbose should be enabled by default

logger = api.get_logger()


class FindOwnerlessCommand(base.ArgparseCommand):
    """
    Command to find and optionally claim ownerless records in the vault.
    
    This command identifies records that don't have an owner and can optionally
    claim them for the current user.
    """

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='find-ownerless', 
            description='List (and, optionally, claim) records in the user\'s vault that currently do not have an owner',
            parents=[base.report_output_parser]
        )
        FindOwnerlessCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add command-specific arguments to the parser."""
        parser.add_argument(
            '--claim', 
            dest='claim', 
            action='store_true', 
            help='Claim the found records as the owner'
        )
        parser.add_argument(
            '-v', '--verbose', 
            action='store_true', 
            help='Output detailed information for each record found'
        )
        parser.add_argument(
            'folder', 
            nargs='*', 
            type=str, 
            action='store', 
            help='Path or UID of folder to search (optional, multiple values allowed)'
        )
        parser.error = base.ArgparseCommand.raise_parse_exception
        parser.exit = base.ArgparseCommand.suppress_exit

    def execute(self, context: KeeperParams, **kwargs):
        """Execute the find-ownerless command."""
        assert context.vault is not None
        vault = context.vault
        
        claim_records = kwargs.get('claim', False)
        output_format = kwargs.get('format', DEFAULT_OUTPUT_FORMAT)
        output_file = kwargs.get('output')
        verbose = kwargs.get('verbose', False) or not claim_records or output_file
        folders = kwargs.get('folder', [])

        ownerless_records = self._fetch_ownerless_records(vault)
        
        if folders and ownerless_records:
            ownerless_records = self._filter_records_by_folders(context, ownerless_records, folders)

        if ownerless_records:
            logger.info(f'Found [{len(ownerless_records)}] ownerless record(s)')
            
            if verbose:
                records_dump = self._dump_record_details(
                    context, ownerless_records, output_file, output_format
                )
            else:
                records_dump = None
                
            if claim_records:
                self._claim_ownerless_records(vault, ownerless_records)
                vault.sync_down(force=True)
                logger.info('Records have been claimed successfully')
            else:
                logger.info('To claim the record(s) found above, re-run this command with the --claim flag.')
                
            return records_dump
        else:
            logger.info('No ownerless records found')
            return None

    def _fetch_ownerless_records(self, vault):
        """Fetch ownerless records from the API."""
        try:
            request = APIRequest_pb2.OwnerlessRecords()
            response = vault.keeper_auth.execute_auth_rest(
                request=request, 
                rest_endpoint=OWNERLESS_RECORDS_GET_ENDPOINT,
                response_type=APIRequest_pb2.OwnerlessRecords
            )
            
            if not response or not response.ownerlessRecord:
                return []
                
            record_uids = {utils.base64_url_encode(rec.recordUid) for rec in response.ownerlessRecord if rec}
            records = [vault.vault_data.get_record(uid) for uid in record_uids]
            
            return [record for record in records if record is not None]
            
        except Exception as e:
            logger.error(f"Failed to fetch ownerless records: {e}")
            return []

    def _filter_records_by_folders(self, context, records, folders):
        """Filter records to only include those in the specified folders."""
        folder_record_uids = set()
        for folder_path in folders:
            contained_records = share_utils.get_contained_record_uids(context, folder_path, False)
            for record_uids in contained_records.values():
                folder_record_uids.update(record_uids)
        
        return [record for record in records if record.record_uid in folder_record_uids]

    def _create_ownerless_record_request(self, vault, records):
        """Create API request parameters for ownerless records."""
        request_params = []
        
        for record in records:
            try:
                record_key = vault.vault_data.get_record_key(record.record_uid)
                encrypted_key = crypto.encrypt_aes_v1(record_key, vault.keeper_auth.auth_context.data_key)
                
                ownerless_record = APIRequest_pb2.OwnerlessRecord()
                ownerless_record.recordUid = utils.base64_url_decode(record.record_uid)
                ownerless_record.recordKey = encrypted_key
                
                request_params.append(ownerless_record)
                
            except Exception as e:
                logger.warning(f"Failed to prepare record {record.record_uid} for claiming: {e}")
                
        return request_params

    def _claim_ownerless_records(self, vault, records):
        """Claim the specified ownerless records."""
        if not records:
            return
            
        chunk_size = CHUNK_SIZE
        total_claimed = 0
        
        for i in range(0, len(records), chunk_size):
            chunk = records[i:i + chunk_size]
            request_params = self._create_ownerless_record_request(vault, chunk)
            
            if not request_params:
                continue
                
            try:
                request = APIRequest_pb2.OwnerlessRecords()
                request.ownerlessRecord.extend(request_params)
                
                vault.keeper_auth.execute_auth_rest(
                    request=request, 
                    rest_endpoint=OWNERLESS_RECORDS_SET_OWNER_ENDPOINT, 
                    response_type=APIRequest_pb2.OwnerlessRecords
                )
                
                total_claimed += len(request_params)
                logger.debug(f"Claimed {len(request_params)} records in chunk {i//chunk_size + 1}")
                
            except Exception as e:
                logger.error(f"Failed to claim records in chunk {i//chunk_size + 1}: {e}")

    def _dump_record_details(self, context, records, output_file, output_format):
        """Generate detailed report of ownerless records."""
        if not records:
            return None
            
        record_uids = {record.record_uid for record in records}
        shared_records = share_utils.get_shared_records(context, record_uids).values()
        
        headers = ['record_uid', 'title', 'shared_with', 'folder_path']
        table_data = []
        
        for shared_record in shared_records:
            folder_paths = vault_utils.get_folders_for_record(context.vault.vault_data, shared_record.record_uid)
            folder_path = '/'.join([folder.name for folder in folder_paths]) if folder_paths else ''
            
            admin_usernames = shared_record.get_all_share_admins()
            
            row = [
                shared_record.record_uid,
                shared_record.title,
                admin_usernames,
                folder_path
            ]
            table_data.append(row)
        
        if output_format != 'json':
            headers = [report_utils.field_to_title(header) for header in headers]
            
        return report_utils.dump_report_data(
            table_data, 
            headers, 
            fmt=output_format, 
            filename=output_file, 
            row_number=True
        )

