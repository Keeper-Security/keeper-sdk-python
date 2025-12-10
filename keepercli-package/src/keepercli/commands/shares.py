import argparse
import datetime
import math
import re
from enum import Enum
from typing import Optional

from keepersdk import utils
from keepersdk.authentication import keeper_auth
from keepersdk.proto import record_pb2, APIRequest_pb2
from keepersdk.vault import ksm_management, vault_online, vault_utils, share_management_utils
from keepersdk.vault.shares_management import RecordShares, FolderShares

from . import base
from .. import api, prompt_utils, constants
from ..helpers import folder_utils, record_utils, report_utils, timeout_utils
from ..params import KeeperParams


class ApiUrl(Enum):
    SHARE_ADMIN = 'vault/am_i_share_admin'
    SHARE_UPDATE = 'vault/records_share_update'
    SHARE_FOLDER_UPDATE = 'vault/shared_folder_update_v3'
    REMOVE_EXTERNAL_SHARE = 'vault/external_share_remove'


class ShareAction(Enum):
    GRANT = 'grant'
    REVOKE = 'revoke'
    OWNER = 'owner'
    CANCEL = 'cancel'
    REMOVE = 'remove'


class ManagePermission(Enum):
    ON = 'on'
    OFF = 'off'


logger = api.get_logger()

# Constants
TIMESTAMP_MILLISECONDS_FACTOR = 1000
TRUNCATE_SUFFIX = '...'
URL_TRUNCATE_LENGTH = 30
NON_SHARED_DEFAULT = 'non-shared'
CUSTOM_FIELD_TYPE_PREFIX = 'type:'
TOTP_FIELD_NAME = 'totp'
LIST_SEPARATOR = '|'
DICT_SEPARATOR = ';'
KEY_VALUE_SEPARATOR = '='
PERMISSION_SEPARATOR = '='
SHARE_NAMES_SEPARATOR = ', '
SUPPORTED_RECORD_VERSIONS = {2, 3}
DEFAULT_SEARCH_FIELDS = ['by_title', 'by_login', 'by_password']
CHUNK_SIZE = 500
MAX_BATCH_SIZE = 1000
SHARE_LINK_TRUNCATE_LENGTH = 20
SIX_MONTHS_IN_SECONDS = 182 * 24 * 60 * 60
TEAMS_THRESHOLD = 500
ALL_FOLDERS_WILDCARD = '*'
ALL_USERS_WILDCARD = '@existing'
ALL_USERS_WILDCARD_ALT = '@current'
DEFAULT_ACCOUNT_WILDCARD = '*'
DEFAULT_RECORD_WILDCARD = '*'

def set_expiration_fields(obj, expiration):
    """Set expiration and timerNotificationType fields on proto object if expiration is provided."""
    if isinstance(expiration, int):
        if expiration > 0:
            obj.expiration = expiration * TIMESTAMP_MILLISECONDS_FACTOR
            obj.timerNotificationType = record_pb2.NOTIFY_OWNER
        elif expiration < 0:
            obj.expiration = -1


class ShareRecordCommand(base.ArgparseCommand):
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='share-record',
            description='Change the sharing permissions of an individual record'
        )
        ShareRecordCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):

        parser.add_argument(
            '-e', '--email', dest='email', action='append', help='account email'
        )
        parser.add_argument(
            '--contacts-only', action='store_true', 
            help="Share only to known targets; Allows routing to alternate domains with matching usernames if needed"
        )
        parser.add_argument(
            '-f', '--force', action='store_true', help='Skip confirmation prompts'
        )
        parser.add_argument(
            '-a', '--action', dest='action', choices=[action.value for action in ShareAction],
            default=ShareAction.GRANT.value, action='store', help='user share action. \'grant\' if omitted'
        )
        parser.add_argument(
            '-s', '--share', dest='can_share', action='store_true', help='can re-share record'
        )
        parser.add_argument(
            '-w', '--write', dest='can_edit', action='store_true', help='can modify record'
        )
        parser.add_argument(
            '-R', '--recursive', dest='recursive', action='store_true', 
            help='apply command to shared folder hierarchy'
        )
        parser.add_argument(
            '--dry-run', dest='dry_run', action='store_true', 
            help='display the permissions changes without committing them'
        )
        expiration = parser.add_mutually_exclusive_group()
        expiration.add_argument(
            '--expire-at', dest='expire_at', action='store', help='share expiration: never or UTC datetime'
        )
        expiration.add_argument(
            '--expire-in', dest='expire_in', action='store', 
            metavar='<NUMBER>[(mi)nutes|(h)ours|(d)ays|(mo)nths|(y)ears]',
            help='share expiration: never or period'
        )
        parser.add_argument(
            'record', nargs='?', type=str, action='store', help='record/shared folder path/UID'
        )
    
    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")
        vault = context.vault
        
        uid_or_name = kwargs.get('record')
        if not uid_or_name:
            return self.get_parser().print_help()
        
        emails = kwargs.get('email') or []
        if not emails:
            raise ValueError('\'email\' parameter is missing')
        
        action = kwargs.get('action', ShareAction.GRANT.value)
        
        if kwargs.get('contacts_only'):
            emails = self._validate_and_replace_contacts(vault, emails, kwargs.get('force'))
        
        if action == ShareAction.CANCEL.value:
            RecordShares.cancel_share(vault, emails)
            vault.sync_down()
            return
        
        share_expiration = share_management_utils.get_share_expiration(
            kwargs.get('expire_at'), kwargs.get('expire_in')
        )
        
        request = RecordShares.prep_request(
            vault=vault, 
            enterprise=context.enterprise_data,
            uid_or_name=uid_or_name, 
            emails=emails, 
            share_expiration=share_expiration, 
            action=action, 
            dry_run=kwargs.get('dry_run', False), 
            can_edit=kwargs.get('can_edit'), 
            can_share=kwargs.get('can_share'), 
            recursive=kwargs.get('recursive')
        )
        if request:
            success_responses, failed_responses = RecordShares.send_requests(vault, [request])
            if success_responses:
                logger.info(f'{len(success_responses)} share requests were successfully processed')
            if failed_responses:
                logger.error(f'{len(failed_responses)} share requests failed to process')
                for failed_response in failed_responses:
                    logger.error(f'Failed to process share request: {failed_response}')
            vault.sync_down()
    
    def _validate_and_replace_contacts(self, vault, emails: list, force: bool) -> list:
        """Validate emails against known contacts and optionally replace with matches."""
        shared_objects = share_management_utils.get_share_objects(vault=vault)
        known_users = shared_objects.get('users', {})
        known_emails = [u.casefold() for u in known_users.keys()]
        
        def is_unknown(email):
            return email.casefold() not in known_emails and utils.is_email(email)
        
        unknowns = [e for e in emails if is_unknown(e)]
        if not unknowns:
            return emails
        
        username_map = {
            e: ShareRecordCommand.get_contact(e, known_users) 
            for e in unknowns
        }
        table = [[k, v] for k, v in username_map.items()]
        logger.info(f'{len(unknowns)} unrecognized share recipient(s) and closest matching contact(s)')
        report_utils.dump_report_data(table, ['Username', 'From Contacts'])
        
        confirmed = force or prompt_utils.user_choice(
            '\tReplace with known matching contact(s)?', 'yn', default='n'
        ) == 'y'
        
        if not confirmed:
            return emails
        
        good_emails = [e for e in emails if e not in unknowns]
        replacements = [e for e in username_map.values() if e]
        return [*good_emails, *replacements]
    
    @staticmethod
    def get_contact(user, contacts):
        if not user or not contacts:
            return None
            
        user_username = user.split('@')[0].casefold()
        
        for contact in contacts:
            contact_username = contact.split('@')[0].casefold()
            if user_username == contact_username:
                return contact
                
        return None


class ShareFolderCommand(base.ArgparseCommand):
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='share-folder',
            description='Change the sharing permissions of shared folders'
        )
        ShareFolderCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
        
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '-a', '--action', dest='action', choices=[ShareAction.GRANT.value, ShareAction.REMOVE.value], 
            default=ShareAction.GRANT.value, action='store', 
            help='shared folder action. \'grant\' if omitted'
        )
        parser.add_argument(
            '-e', '--email', dest='user', action='append',
            help='account email, team, @existing for all users and teams in the folder, or \'*\' as default folder permission'
        )
        parser.add_argument(
            '-r', '--record', dest='record', action='append', 
            help='record name, record UID, @existing for all records in the folder, or \'*\' as default folder permission'
        )
        parser.add_argument(
            '-p', '--manage-records', dest='manage_records', action='store', 
            choices=[perm.value for perm in ManagePermission], help='account permission: can manage records.'
        )
        parser.add_argument(
            '-o', '--manage-users', dest='manage_users', action='store', 
            choices=[perm.value for perm in ManagePermission], help='account permission: can manage users.'
        )
        parser.add_argument(
            '-s', '--can-share', dest='can_share', action='store', 
            choices=[perm.value for perm in ManagePermission], help='record permission: can be shared'
        )
        parser.add_argument(
            '-d', '--can-edit', dest='can_edit', action='store', 
            choices=[perm.value for perm in ManagePermission], help='record permission: can be modified.'
        )
        parser.add_argument(
            '-f', '--force', dest='force', action='store_true', 
            help='Apply permission changes ignoring default folder permissions. Used on the initial sharing action'
        )
        expiration = parser.add_mutually_exclusive_group()
        expiration.add_argument(
            '--expire-at', dest='expire_at', action='store', metavar='TIMESTAMP', 
            help='share expiration: never or ISO datetime (yyyy-MM-dd[ hh:mm:ss])'
        )
        expiration.add_argument(
            '--expire-in', dest='expire_in', action='store', metavar='PERIOD', 
            help='share expiration: never or period (<NUMBER>[(y)ears|(mo)nths|(d)ays|(h)ours(mi)nutes]'
        )
        parser.add_argument(
            'folder', nargs='+', type=str, action='store', help='shared folder path or UID'
        )
    
    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError('Vault is not initialized.')
        
        vault = context.vault
        names = self._normalize_folder_names(kwargs.get('folder'))
        shared_folder_uids = self._resolve_shared_folder_uids(vault, names)
        
        if not shared_folder_uids:
            raise ValueError('Enter name of at least one existing folder')

        action = kwargs.get('action') or ShareAction.GRANT.value
        share_expiration = self._get_share_expiration(action, kwargs)
        
        user_data = self._parse_user_arguments(vault, kwargs)
        record_data = self._parse_record_arguments(vault, kwargs)
        
        if self._is_nothing_to_do(user_data, record_data):
            logger.info('Nothing to do')
            return

        rq_groups = self._prepare_request_groups(
            vault, shared_folder_uids, user_data, record_data, 
            action, share_expiration, kwargs
        )
        success_responses, failed_responses = FolderShares.send_requests(vault=vault, partitioned_requests=rq_groups)
        if success_responses:
            logger.info(f'{len(success_responses)} share requests were successfully processed')
        if failed_responses:
            logger.error(f'{len(failed_responses)} share requests failed to process')
            for failed_response in failed_responses:
                logger.error(f'Failed to process share request: {failed_response}')
        vault.sync_down()
    
    def _normalize_folder_names(self, folder_names) -> list:
        """Normalize folder names list and check for wildcard."""
        if not folder_names:
            return []
        if not isinstance(folder_names, list):
            return [folder_names]
        return folder_names
    
    def _resolve_shared_folder_uids(self, vault: vault_online.VaultOnline, names: list) -> set:
        """Resolve folder names to shared folder UIDs."""
        all_folders = any(x == ALL_FOLDERS_WILDCARD for x in names)
        if all_folders:
            names = [x for x in names if x != ALL_FOLDERS_WILDCARD]
        
        shared_folder_cache = {x.shared_folder_uid: x for x in vault.vault_data.shared_folders()}
        folder_cache = {x.folder_uid: x for x in vault.vault_data.folders()}
        shared_folder_uids = set()
        
        if all_folders:
            shared_folder_uids.update(shared_folder_cache.keys())
        else:
            shared_folder_uids = self._resolve_specific_folders(
                vault, names, shared_folder_cache, folder_cache
            )
        
        return shared_folder_uids
    
    def _resolve_specific_folders(self, vault: vault_online.VaultOnline, names: list, 
                                   shared_folder_cache: dict, folder_cache: dict) -> set:
        """Resolve specific folder names to shared folder UIDs."""
        shared_folder_uids = set()
        folder_uids = {
            uid 
            for name in names if name 
            for uid in share_management_utils.get_folder_uids(vault, name)
        }
        
        folders = {folder_cache.get(uid) for uid in folder_uids if folder_cache.get(uid)}
        shared_folder_uids.update([uid for uid in folder_uids if uid in shared_folder_cache])
        
        sf_subfolders = {f for f in folders if f and f.folder_type == 'shared_folder_folder'}
        shared_folder_uids.update({f.folder_scope_uid for f in sf_subfolders if f.folder_scope_uid})
        
        unresolved_names = [
            name for name in names 
            if name and not share_management_utils.get_folder_uids(vault, name)
        ]
        if unresolved_names:
            share_admin_folder_uids = self._get_share_admin_obj_uids(
                vault, unresolved_names, record_pb2.CHECK_SA_ON_SF
            )
            shared_folder_uids.update(share_admin_folder_uids or [])
        
        return shared_folder_uids
    
    def _get_share_admin_obj_uids(self, vault: vault_online.VaultOnline, 
                                   obj_names: list, obj_type) -> Optional[set]:
        """Get UIDs of objects where user is share admin."""
        if not obj_names:
            return None
        try:
            rq = record_pb2.AmIShareAdmin()
            for name in obj_names:
                try:
                    uid = utils.base64_url_decode(name)
                    if isinstance(uid, bytes) and len(uid) == 16:
                        osa = record_pb2.IsObjectShareAdmin()
                        osa.uid = uid
                        osa.objectType = obj_type
                        rq.isObjectShareAdmin.append(osa)
                except Exception:
                    pass
            
            if len(rq.isObjectShareAdmin) == 0:
                return None
            
            rs = vault.keeper_auth.execute_auth_rest(
                rest_endpoint=ApiUrl.SHARE_ADMIN.value, 
                request=rq, 
                response_type=record_pb2.AmIShareAdmin
            )
            if rs and hasattr(rs, 'isObjectShareAdmin'):
                sa_obj_uids = {sa_obj.uid for sa_obj in rs.isObjectShareAdmin if sa_obj.isAdmin}
                return {utils.base64_url_encode(uid) for uid in sa_obj_uids}
            return None
        except (ValueError, AttributeError) as e:
            raise ValueError(f'get_share_admin: msg = {e}') from e
    
    def _get_record_uids(self, vault: vault_online.VaultOnline, name: str) -> set[str]:
        """Get record UIDs by name or UID."""
        record_uids = set()
        if not vault or not vault.vault_data:
            return record_uids
        
        record = vault.vault_data.get_record(name)
        if record:
            record_uids.add(name)
            return record_uids
        
        for record_info in vault.vault_data.records():
            if record_info.title == name:
                record_uids.add(record_info.record_uid)
        
        return record_uids
    
    def _get_share_expiration(self, action: str, kwargs: dict):
        """Get share expiration if action is grant."""
        if action == ShareAction.GRANT.value:
            return share_management_utils.get_share_expiration(
                kwargs.get('expire_at'), kwargs.get('expire_in')
            )
        return None
    
    def _parse_user_arguments(self, vault, kwargs: dict) -> dict:
        """Parse user arguments and return user data."""
        as_users = set()
        as_teams = set()
        all_users = False
        default_account = False
        
        if 'user' not in kwargs:
            return {
                'users': as_users,
                'teams': as_teams,
                'all_users': all_users,
                'default_account': default_account
            }
        
        for u in (kwargs.get('user') or []):
            if u == DEFAULT_ACCOUNT_WILDCARD:
                default_account = True
            elif u in (ALL_USERS_WILDCARD, ALL_USERS_WILDCARD_ALT):
                all_users = True
            elif re.match(constants.EMAIL_PATTERN, u):
                as_users.add(u.lower())
            else:
                team_uid = self._resolve_team_uid(vault, u)
                if team_uid:
                    as_teams.add(team_uid)
        
        return {
            'users': as_users,
            'teams': as_teams,
            'all_users': all_users,
            'default_account': default_account
        }
    
    def _resolve_team_uid(self, vault, team_identifier: str) -> Optional[str]:
        """Resolve team identifier to team UID."""
        teams = share_management_utils.get_share_objects(vault=vault).get('teams', {})
        teams_map = {uid: team.get('name') for uid, team in teams.items()}
        
        if len(teams) >= TEAMS_THRESHOLD:
            teams = vault_utils.load_available_teams(auth=vault.keeper_auth)
            teams_map.update({t.team_uid: t.name for t in teams})
        
        matches = [uid for uid, name in teams_map.items() if team_identifier in (name, uid)]
        
        if len(matches) == 0:
            logger.warning(f'User "{team_identifier}" could not be resolved as email or team')
            return None
        elif len(matches) > 1:
            logger.warning(
                f'Multiple matches were found for team "{team_identifier}". '
                f'Try using its UID -- which can be found via `list-team` -- instead'
            )
            return None
        
        return matches[0]
    
    def _parse_record_arguments(self, vault, kwargs: dict) -> dict:
        """Parse record arguments and return record data."""
        record_uids = set()
        all_records = False
        default_record = False
        
        if 'record' not in kwargs:
            return {
                'record_uids': record_uids,
                'all_records': all_records,
                'default_record': default_record
            }
        
        records = kwargs.get('record') or []
        unresolved_names = []
        
        for r in records:
            if r == DEFAULT_RECORD_WILDCARD:
                default_record = True
            elif r in (ALL_USERS_WILDCARD, ALL_USERS_WILDCARD_ALT):
                all_records = True
            else:
                r_uids = self._get_record_uids(vault, r)
                if r_uids:
                    record_uids.update(r_uids)
                else:
                    unresolved_names.append(r)
        
        if unresolved_names:
            sa_record_uids = self._get_share_admin_obj_uids(
                vault, unresolved_names, record_pb2.CHECK_SA_ON_RECORD
            )
            record_uids.update(sa_record_uids or {})
        
        return {
            'record_uids': record_uids,
            'all_records': all_records,
            'default_record': default_record
        }
    
    def _is_nothing_to_do(self, user_data: dict, record_data: dict) -> bool:
        """Check if there's nothing to do based on user and record data."""
        return (
            len(user_data['users']) == 0 and 
            len(user_data['teams']) == 0 and 
            len(record_data['record_uids']) == 0 and
            not record_data['default_record'] and 
            not user_data['default_account'] and
            not user_data['all_users'] and 
            not record_data['all_records']
        )
    
    def _prepare_request_groups(self, vault: vault_online.VaultOnline, shared_folder_uids: set,
                                user_data: dict, record_data: dict, action: str,
                                share_expiration, kwargs: dict) -> list:
        """Prepare request groups for all shared folders."""
        rq_groups = []
        shared_folder_cache = {x.shared_folder_uid: x for x in vault.vault_data.shared_folders()}
        
        for sf_uid in shared_folder_uids:
            folder_requests = self._prepare_folder_requests(
                vault, sf_uid, shared_folder_cache, user_data, 
                record_data, action, share_expiration, kwargs
            )
            rq_groups.extend(folder_requests)
        
        return rq_groups
    
    def _prepare_folder_requests(self, vault: vault_online.VaultOnline, sf_uid: str,
                                  shared_folder_cache: dict, user_data: dict, 
                                  record_data: dict, action: str, share_expiration,
                                  kwargs: dict) -> list:
        """Prepare requests for a single shared folder."""
        sf_users = user_data['users'].copy()
        sf_teams = user_data['teams'].copy()
        sf_records = record_data['record_uids'].copy()
        
        sh_fol = self._load_or_create_shared_folder(
            vault, sf_uid, shared_folder_cache, user_data, record_data, action
        )
        
        if sf_uid in shared_folder_cache and sh_fol:
            self._update_from_existing_folder(
                sh_fol, vault.keeper_auth, user_data, record_data, sf_users, sf_records
            )
        
        return self._chunk_and_prepare_requests(
            vault, kwargs, sh_fol, sf_uid, sf_users, sf_teams, sf_records,
            record_data['default_record'], user_data['default_account'], share_expiration
        )
    
    def _load_or_create_shared_folder(self, vault: vault_online.VaultOnline, sf_uid: str, shared_folder_cache: dict,
                                       user_data: dict, record_data: dict, action: str):
        """Load existing shared folder or create a new one."""
        if sf_uid in shared_folder_cache:
            return vault.vault_data.load_shared_folder(sf_uid)
        
        return {
            'shared_folder_uid': sf_uid,
            'users': [
                {
                    'username': x, 
                    'manage_records': action != ShareAction.GRANT.value, 
                    'manage_users': action != ShareAction.GRANT.value
                }
                for x in user_data['users']
            ],
            'teams': [
                {
                    'team_uid': x, 
                    'manage_records': action != ShareAction.GRANT.value, 
                    'manage_users': action != ShareAction.GRANT.value
                }
                for x in user_data['teams']
            ],
            'records': [
                {
                    'record_uid': x, 
                    'can_share': action != ShareAction.GRANT.value, 
                    'can_edit': action != ShareAction.GRANT.value
                }
                for x in record_data['record_uids']
            ]
        }
    
    def _update_from_existing_folder(self, sh_fol, auth: keeper_auth.KeeperAuth, 
                                     user_data: dict, record_data: dict,
                                     sf_users: set, sf_records: set):
        """Update user and record sets from existing folder permissions."""
        if not (user_data['all_users'] or record_data['all_records']):
            return
        
        if user_data['all_users'] and sh_fol.user_permissions:
            sf_users.update(
                x.name for x in sh_fol.user_permissions 
                if x.name != auth.auth_context.username
            )
        
        if record_data['all_records'] and sh_fol.record_permissions:
            sf_records.update(x.record_uid for x in sh_fol.record_permissions)
    
    def _chunk_and_prepare_requests(self, vault: vault_online.VaultOnline, kwargs: dict, sh_fol, sf_uid: str,
                                     sf_users: set, sf_teams: set, sf_records: set,
                                     default_record: bool, default_account: bool,
                                     share_expiration) -> list:
        """Chunk records and users, then prepare requests."""
        rec_list = list(sf_records)
        user_list = list(sf_users)
        num_rec_chunks = math.ceil(len(sf_records) / CHUNK_SIZE) or 1
        num_user_chunks = math.ceil(len(sf_users) / CHUNK_SIZE) or 1
        num_rq_groups = num_user_chunks * num_rec_chunks
        
        rq_groups = [[] for _ in range(num_rq_groups)]
        rec_chunks = [
            rec_list[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE] 
            for i in range(num_rec_chunks)
        ] or [[]]
        user_chunks = [
            user_list[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE] 
            for i in range(num_user_chunks)
        ] or [[]]
        
        shared_folder_revision = vault.vault_data.storage.shared_folders.get_entity(sf_uid).revision
        sf_unencrypted_key = vault.vault_data.get_shared_folder_key(shared_folder_uid=sf_uid)
        
        group_idx = 0
        for r_chunk in rec_chunks:
            for u_chunk in user_chunks:
                sf_info = self._build_shared_folder_info(
                    sh_fol, sf_uid, sf_unencrypted_key, shared_folder_revision, group_idx
                )
                request = FolderShares.prepare_request(
                    vault, kwargs, sf_info, u_chunk, sf_teams, r_chunk,
                    default_record=default_record,
                    default_account=default_account,
                    share_expiration=share_expiration
                )
                rq_groups[group_idx].append(request)
                group_idx += 1
        
        return rq_groups
    
    def _build_shared_folder_info(self, sh_fol, sf_uid: str, sf_unencrypted_key,
                                   shared_folder_revision: int, group_idx: int) -> dict:
        """Build shared folder info dictionary."""
        if isinstance(sh_fol, dict):
            sf_info = sh_fol.copy()
            if group_idx > 0 and 'revision' in sf_info:
                del sf_info['revision']
            return sf_info
        
        sf_info = {
            'shared_folder_uid': sf_uid,
            'users': sh_fol.user_permissions,
            'teams': [],
            'records': sh_fol.record_permissions,
            'shared_folder_key_unencrypted': sf_unencrypted_key,
            'default_manage_users': sh_fol.default_can_share,
            'default_manage_records': sh_fol.default_can_edit,
            'revision': shared_folder_revision
        }
        if group_idx > 0:
            del sf_info['revision']
        
        return sf_info


class OneTimeShareListCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='share-list',
            description='Displays a list of one-time shares for a record',
            parents=[base.report_output_parser]
        )
        OneTimeShareListCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '-R', '--recursive', dest='recursive', action='store_true', 
            help='Traverse recursively through subfolders'
        )
        parser.add_argument(
            '-v', '--verbose', dest='verbose', action='store_true', help='verbose output.'
        )
        parser.add_argument(
            '-a', '--all', dest='show_all', action='store_true', help='show all one-time shares including expired.'
        )
        parser.add_argument(
            'record', nargs='?', type=str, action='store', help='record/folder path/UID'
        )

    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise ValueError('Vault is not initialized.')
        
        vault = context.vault
        
        records = kwargs['record'] if 'record' in kwargs else None
        if not records:
            self.get_parser().print_help()
            return
        if isinstance(records, str):
            records = [records]
        
        record_uids = self._resolve_record_uids(context, vault, records, kwargs.get('recursive', False))
        if not record_uids:
            raise base.CommandError('No records found')

        applications = self._get_applications(vault, record_uids)
        table_data = self._build_share_table(applications, kwargs)
        
        return self._format_output(table_data, kwargs)

    def _resolve_record_uids(self, context: KeeperParams, vault, records: list, recursive: bool) -> set:
        """Resolve record names/paths to UIDs."""
        record_uids = set()
        
        for name in records:
            record_uid = None
            folder_uid = None
            if name in vault.vault_data._records:
                record_uid = name
            elif name in vault.vault_data._folders:
                folder_uid = name
            else:
                rs = folder_utils.try_resolve_path(context, name)
                if rs is not None:
                    folder, r_name = rs
                    if r_name:
                        f_uid = folder.folder_uid or ''
                        if f_uid in vault.vault_data._folders:
                            for uid in folder.records:
                                rec = vault.vault_data.get_record(record_uid=uid)
                                if rec and rec.version in SUPPORTED_RECORD_VERSIONS and rec.title.lower() == r_name.lower():
                                    record_uid = uid
                                    break
                    else:
                        folder_uid = folder.folder_uid or ''
            
            if record_uid is not None:
                record_uids.add(record_uid)
            elif folder_uid is not None:
                self._add_folder_records(vault, folder_uid, record_uids, recursive)
        
        return record_uids

    def _add_folder_records(self, vault, folder_uid: str, record_uids: set, recursive: bool):
        """Add records from a folder to the record_uids set."""
        def on_folder(f):
            f_uid = f.folder_uid or ''
            if f_uid in vault.vault_data._folders:
                folder = vault.vault_data.get_folder(folder_uid=f_uid)
                recs = folder.records
                if recs:
                    record_uids.update(recs)

        folder = vault.vault_data.get_folder(folder_uid=folder_uid)
        if recursive:
            vault_utils.traverse_folder_tree(vault.vault_data, folder, on_folder)
        else:
            on_folder(folder)

    def _get_applications(self, vault, record_uids: set):
        """Get application info for the given record UIDs."""
        r_uids = list(record_uids)
        if len(r_uids) >= MAX_BATCH_SIZE:
            logger.info('Trimming result to %d records', MAX_BATCH_SIZE)
            r_uids = r_uids[:MAX_BATCH_SIZE - 1]
        return ksm_management.get_app_info(vault=vault, app_uid=r_uids)

    def _build_share_table(self, applications, kwargs):
        """Build table data from applications."""
        show_all = kwargs.get('show_all', False)
        verbose = kwargs.get('verbose', False)
        now = utils.current_milli_time()
        
        fields = ['record_uid', 'share_link_name', 'share_link_id', 'generated', 'opened', 'expires']
        if show_all:
            fields.append('status')
        
        table = []
        output_format = kwargs.get('format')
        
        for app_info in applications:
            if not app_info.isExternalShare:
                continue
                
            for client in app_info.clients:
                if not show_all and now > client.accessExpireOn:
                    continue
                    
                link = self._create_share_link_data(app_info, client, verbose, output_format, now)
                table.append([link.get(x, '') for x in fields])
        
        return table, fields

    def _create_share_link_data(self, app_info, client, verbose: bool, output_format: str, now: int):
        """Create share link data dictionary."""
        encoded_client_id = utils.base64_url_encode(client.clientId)
        link = {
            'record_uid': utils.base64_url_encode(app_info.appRecordUid),
            'name': client.id,
            'share_link_id': encoded_client_id,
            'generated': datetime.datetime.fromtimestamp(client.createdOn / TIMESTAMP_MILLISECONDS_FACTOR),
            'expires': datetime.datetime.fromtimestamp(client.accessExpireOn / TIMESTAMP_MILLISECONDS_FACTOR),
        }
        
        if output_format == 'table' and not verbose:
            link['share_link_id'] = encoded_client_id[:SHARE_LINK_TRUNCATE_LENGTH] + TRUNCATE_SUFFIX
        else:
            link['share_link_id'] = encoded_client_id

        if client.firstAccess > 0:
            link['opened'] = datetime.datetime.fromtimestamp(client.firstAccess / TIMESTAMP_MILLISECONDS_FACTOR)
            link['accessed'] = datetime.datetime.fromtimestamp(client.lastAccess / TIMESTAMP_MILLISECONDS_FACTOR)

        if now > client.accessExpireOn:
            link['status'] = 'Expired'
        elif client.firstAccess > 0:
            link['status'] = 'Opened'
        else:
            link['status'] = 'Generated'
        
        return link

    def _format_output(self, table_data, kwargs):
        """Format and return the output."""
        table, fields = table_data
        output_format = kwargs.get('format')
        
        if output_format == 'table':
            fields = [report_utils.field_to_title(x) for x in fields]
        
        return report_utils.dump_report_data(table, fields, fmt=output_format, filename=kwargs.get('output'))


class OneTimeShareCreateCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='share-create',
            description='Creates one-time share URL for a record'
        )
        OneTimeShareCreateCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '--output', dest='output', choices=['clipboard', 'stdout'], action='store', 
            help='URL output destination'
        )
        parser.add_argument(
            '--name', dest='share_name', action='store', help='one-time share URL name'
        )
        parser.add_argument(
            '-e', '--expire', dest='expire', action='store', metavar='<NUMBER>[(mi)nutes|(h)ours|(d)ays]', 
            help='time period record share URL is valid.'
        )
        parser.add_argument(
            '--editable', dest='is_editable', action='store_true', help='allow the user to edit the shared record'
        )
        parser.add_argument(
            'record', nargs='?', type=str, action='store', help='record path or UID. Can be repeated'
        )

    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise ValueError('Vault is not initialized.')
        
        vault = context.vault

        record_names = kwargs.get('record')
        period_str = kwargs.get('expire')
        name = kwargs.get('share_name', '')
        is_editable = kwargs.get('is_editable', False)
        if isinstance(record_names, str):
            record_names = [record_names]
        if not record_names:
            self.get_parser().print_help()
            raise base.CommandError('No records provided')
        if not period_str:
            self.get_parser().print_help()
            raise base.CommandError('URL expiration period parameter \"--expire\" is required.')
        
        period = self._validate_and_parse_expiration(period_str)
        
        urls = self._create_share_urls(context, vault, record_names, period, name, is_editable)
        
        return self._handle_output(context, urls, kwargs)

    def _validate_and_parse_expiration(self, period_str):
        """Validate and parse the expiration period."""
        period = timeout_utils.parse_timeout(period_str)
        if period.total_seconds() > SIX_MONTHS_IN_SECONDS:
            raise base.CommandError('URL expiration period cannot be greater than 6 months.')
        return period

    def _create_share_urls(self, context: KeeperParams, vault, record_names: list, period, name: str, is_editable: bool):
        """Create share URLs for the given records."""
        urls = {}
        for record_name in record_names:
            record_uid = record_utils.resolve_record(context=context, name=record_name)
            record = vault.vault_data.load_record(record_uid=record_uid)
            url = record_utils.process_external_share(
                context=context, expiration_period=period, record=record, name=name, is_editable=is_editable, is_self_destruct=False
            )
            urls[record_uid] = str(url)
        return urls

    def _handle_output(self, context: KeeperParams, urls: dict, kwargs):
        """Handle different output formats for the URLs."""
        if context.keeper_config.batch_mode:
            return '\n'.join(urls.values())
        
        output = kwargs.get('output') or ''
        if len(urls) > 1 and not output:
            output = 'stdout'
            
        if output == 'clipboard' and len(urls) == 1:
            return self._copy_to_clipboard(urls)
        elif output == 'stdout':
            return self._output_to_stdout(urls)
        else:
            return '\n'.join(urls.values())

    def _copy_to_clipboard(self, urls: dict):
        """Copy URL to clipboard."""
        import pyperclip
        url = next(iter(urls.values()))
        pyperclip.copy(url)
        logger.info('One-Time record share URL is copied to clipboard')
        return None

    def _output_to_stdout(self, urls: dict):
        """Output URLs to stdout in table format."""
        table = [list(x) for x in urls.items()]
        headers = ['Record UID', 'URL']
        report_utils.dump_report_data(table, headers)
        return None


class OneTimeShareRemoveCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog = 'share-remove',
            description= 'Removes one-time share URL for a record'
        )
        OneTimeShareRemoveCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            'record', nargs='?', type=str, action='store', help='record path or UID'
        )
        parser.add_argument(
            'share', nargs='?', type=str, action='store', help='one-time share name or ID'
        )
    
    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise ValueError('Vault is not initialized.')
        
        vault = context.vault

        record_name = kwargs.get('record')
        if not record_name:
            self.get_parser().print_help()
            return

        record_uid = record_utils.resolve_record(context=context, name=record_name)
        applications = ksm_management.get_app_info(vault=vault, app_uid=record_uid)
        
        if len(applications) == 0:
            logger.info('There are no one-time shares for record \"%s\"', record_name)
            return

        share_name = kwargs.get('share')
        if not share_name:
            self.get_parser().print_help()
            return

        client_id = self._find_client_id(applications, share_name)
        if not client_id:
            return

        self._remove_share(vault, record_uid, client_id, share_name, record_name)

    def _find_client_id(self, applications, share_name: str) -> Optional[bytes]:
        
        cleaned_name = share_name[:-len(TRUNCATE_SUFFIX)] if share_name.endswith(TRUNCATE_SUFFIX) else share_name
        cleaned_name_lower = cleaned_name.lower()
        
        partial_matches = []
        
        for app_info in applications:
            if not app_info.isExternalShare:
                continue
                
            for client in app_info.clients:
                if client.id.lower() == cleaned_name_lower:
                    return client.clientId
                
                encoded_client_id = utils.base64_url_encode(client.clientId)
                if encoded_client_id == cleaned_name:
                    return client.clientId
                
                if encoded_client_id.startswith(cleaned_name):
                    partial_matches.append(client.clientId)
        
        return self._resolve_partial_matches(partial_matches, share_name)

    def _resolve_partial_matches(self, partial_matches: list[bytes], original_name: str) -> Optional[bytes]:
        """
        Resolve partial matches to a single client ID.
        
        Args:
            partial_matches: List of client IDs that partially match
            original_name: Original share name for error reporting
            
        Returns:
            bytes: Single client ID if exactly one match, None otherwise
        """
        if not partial_matches:
            logger.warning('No one-time share found matching "%s"', original_name)
            return None
            
        if len(partial_matches) == 1:
            return partial_matches[0]
            
        # Multiple matches found
        logger.warning('Multiple one-time shares found matching "%s". Please use a more specific identifier.', original_name)
        return None

    def _remove_share(self, vault, record_uid: str, client_id: bytes, share_name: str, record_name: str):
        """Remove the one-time share."""
        rq = APIRequest_pb2.RemoveAppClientsRequest()
        rq.appRecordUid = utils.base64_url_decode(record_uid)
        rq.clients.append(client_id)

        vault.keeper_auth.execute_auth_rest(request=rq, rest_endpoint=ApiUrl.REMOVE_EXTERNAL_SHARE.value)
        logger.info('One-time share \"%s\" is removed from record \"%s\"', share_name, record_name)
