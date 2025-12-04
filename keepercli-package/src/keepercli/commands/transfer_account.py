import argparse
import os
import logging
from typing import Optional, Dict, Set
from enum import Enum

from keepersdk.enterprise.account_transfer import AccountTransferManager
from keepersdk.authentication import keeper_auth
from keepersdk.enterprise import enterprise_types

from . import base
from ..params import KeeperParams

logger = logging.getLogger(__name__)


# Enums for user status and lock states
class UserStatus(Enum):
    ACTIVE = 'active'
    INVITED = 'invited'
    INACTIVE = 'inactive'


class UserLockState(Enum):
    UNLOCKED = 0
    LOCKED = 1
    DISABLED = 2


class UserLockText(Enum):
    LOCKED = 'Locked'
    DISABLED = 'Disabled'


# ANSI color codes - reusable across the application
class Colors(Enum):
    RED = '\033[91m'
    RESET = '\033[0m'


# Sample mapping file content for documentation
SAMPLE_MAPPING_FILE_CONTENT = """
# Lines starting with #, ;, or - are comments
john.doe@company.com -> admin@company.com
jane.smith@company.com <- admin@company.com  
old.user@company.com = new.admin@company.com
user1@company.com user2@company.com
"""


class EnterpriseTransferAccountCommand(base.ArgparseCommand):
    """Perform a vault transfer of a user account
    
    This command transfers all vault data (records, shared folders, teams,
    user folders) from one or more source users to a target user.
    """

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='transfer-user',
            description='Transfer user account from one user to another'
        )
        EnterpriseTransferAccountCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
        
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '-f', '--force',
            dest='force',
            action='store_true',
            help='do not prompt for confirmation'
        )
        parser.add_argument(
            '--target-user',
            dest='target_user',
            action='store',
            help='email to transfer user(s) to'
        )
        parser.add_argument(
            'email',
            type=str,
            nargs='+',
            metavar="user@company.com OR @filename",
            help='User account email/ID (list of strings["user1@company.com", "user2@company.com"]) or File containing account mappings. '
                 'Use @filename to indicate using mapping file. '
                 f'File format examples:{SAMPLE_MAPPING_FILE_CONTENT}'
        )
    
    def execute(self, context: KeeperParams, **kwargs):
        """Execute the transfer account command
        
        Args:
            context: Keeper parameters with auth and enterprise data
            **kwargs: Command arguments (force, target_user, email)
        """
        if not context.vault:
            raise ValueError('Vault not available. Please ensure you are logged in.')

        enterprise_loader = context.enterprise_loader
        if not enterprise_loader:
            raise ValueError('Enterprise data not available. Please ensure you are logged in as an enterprise admin.')
        
        # Ensure enterprise data is loaded
        logger.info('Loading enterprise data...')
        enterprise_loader.load()
        
        user_lookup = self._build_user_lookup(enterprise_loader.enterprise_data)
        logger.debug(f'Loaded {len(user_lookup)} entries in user lookup table')
        
        transfer_map = self._parse_transfer_arguments(kwargs, user_lookup)
        
        if not transfer_map:
            logger.warning('No user accounts to transfer')
            return
        
        transfer_map = self._validate_transfer_map(transfer_map)
        
        if not transfer_map:
            logger.warning('No valid user accounts to transfer after validation')
            return
        
        if not self._confirm_transfer(kwargs, transfer_map):
            logger.info('Transfer cancelled by user')
            return
        
        auth_context = context.auth
        self._lock_source_users(auth_context, transfer_map, user_lookup)
        
        target_keys = self._load_target_keys(auth_context, transfer_map)
        
        self._execute_transfers(context, transfer_map, target_keys, user_lookup)
        
        logger.info('Reloading enterprise data...')
        enterprise_loader.load(reset=True)
    
    def _build_user_lookup(self, enterprise_data: enterprise_types.IEnterpriseData) -> Dict:
        
        user_lookup = {}
        
        for user in enterprise_data.users.get_all_entities():
            user_dict = {
                'enterprise_user_id': user.enterprise_user_id,
                'username': user.username,
                'status': user.status,
                'lock': user.lock
            }
            
            # Store by user ID
            user_lookup[str(user.enterprise_user_id)] = user_dict
            
            # Store by username (both original case and lowercase)
            if user.username:
                user_lookup[user.username] = user_dict
                user_lookup[user.username.lower()] = user_dict
            else:
                logger.debug(f'Username missing from user id={user.enterprise_user_id}')
        
        return user_lookup
    
    def _parse_transfer_arguments(self,
                                  kwargs,
                                  user_lookup: Dict) -> Dict[str, Set[str]]:
        transfer_map = {}
        target_user = kwargs.get('target_user')
        
        if target_user:
            target_user = self._verify_user(target_user, user_lookup)
        
        for email in kwargs.get('email', []):
            if email.startswith('@'):
                # File input
                self._parse_transfer_file(email[1:], transfer_map, user_lookup)
            else:
                # Single user
                email = self._verify_user(email, user_lookup)
                if email and target_user:
                    if target_user not in transfer_map:
                        transfer_map[target_user] = set()
                    transfer_map[target_user].add(email)
        
        return transfer_map
    
    def _parse_transfer_file(self,
                            filename: str,
                            transfer_map: Dict,
                            user_lookup: Dict):
        """Parse transfer mapping file
        
        Sample mapping file content:
        # Lines starting with #, ;, or - are comments
        john.doe@company.com -> admin@company.com
        jane.smith@company.com <- admin@company.com  
        old.user@company.com = new.admin@company.com
        user1@company.com user2@company.com
        
        Args:
            filename: Path to mapping file
            transfer_map: Transfer map to populate
            user_lookup: User lookup dictionary
        """
        if not os.path.exists(filename):
            logger.warning(f'File "{filename}" does not exist. Skipping...')
            return
        
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line[0] in {'#', ';', '-'}:
                continue
            
            # Parse mapping: from -> to
            p = line.partition('->')
            if p[1] != '->':
                p = line.partition('<-')
                if p[1] != '<-':
                    p = line.partition('=')
                    if p[1] != '=':
                        p = line.partition(' ')
            
            if p[2]:
                user1 = self._verify_user(p[0], user_lookup)
                if user1:
                    user2 = self._verify_user(p[2], user_lookup)
                    if user2:
                        # Determine direction
                        if p[1] == '<-':
                            from_user, to_user = user2, user1
                        else:
                            from_user, to_user = user1, user2
                        
                        if to_user not in transfer_map:
                            transfer_map[to_user] = set()
                        transfer_map[to_user].add(from_user)
            else:
                logger.warning(f'File "{filename}" line {line_num}: invalid mapping "{line}". Skipping...')
    
    def _verify_user(self,
                    username: str,
                    user_lookup: Dict) -> Optional[str]:
        """Verify user exists and is active
        """
        username_clean = username.strip()
        username_lower = username_clean.lower()
        
        enterprise_user = None
        if username_clean in user_lookup:
            enterprise_user = user_lookup[username_clean]
        elif username_lower in user_lookup:
            enterprise_user = user_lookup[username_lower]
        
        if not enterprise_user:
            logger.warning(f'"{username}" is not a known user account. Skipping...')
            logger.debug(f'Available users in lookup: {list(user_lookup.keys())}')
            return None
        
        # Check if user is effectively active (active status + not locked)
        status = enterprise_user['status']
        lock = enterprise_user.get('lock', UserLockState.UNLOCKED.value)
        
        if status == UserStatus.INVITED.value:
            logger.warning(f'"{username}" is a pending account. Skipping...')
            return None
        elif status != UserStatus.ACTIVE.value:
            logger.warning(f'"{username}" is not an active account (status: {status}). Skipping...')
            return None
        elif lock > UserLockState.UNLOCKED.value:
            lock_text = UserLockText.LOCKED.value if lock == UserLockState.LOCKED.value else UserLockText.DISABLED.value
            logger.warning(f'"{username}" account is {lock_text}. Skipping...')
            return None
        
        return enterprise_user['username']
    
    def _validate_transfer_map(self, transfer_map: Dict) -> Dict:
        
        # Check for users that appear as both source and target (circular)
        targets = set(transfer_map.keys())
        sources = set()
        for target in transfer_map:
            sources.update(transfer_map[target])
        
        circular = targets.intersection(sources)
        if circular:
            for email in circular:
                logger.warning(
                    f'User "{email}" appears as both source and target for account transfer. '
                    'This is not allowed. Removing from transfer map...'
                )
                if email in transfer_map:
                    del transfer_map[email]
            
            for target in list(transfer_map.keys()):
                transfer_map[target].difference_update(circular)
                if not transfer_map[target]:
                    del transfer_map[target]
        
        sources.clear()
        duplicates = set()
        for target in transfer_map:
            dups = transfer_map[target].intersection(sources)
            if dups:
                duplicates.update(dups)
            sources.update(transfer_map[target])
        
        if duplicates:
            for email in duplicates:
                logger.warning(
                    f'User "{email}" cannot be moved to multiple targets. Removing...'
                )
            
            for target in list(transfer_map.keys()):
                transfer_map[target].difference_update(duplicates)
                if not transfer_map[target]:
                    del transfer_map[target]
        
        return transfer_map
    
    def _confirm_transfer(self, kwargs, transfer_map: Dict) -> bool:
        if kwargs.get('force'):
            return True
        
        source_count = sum(len(sources) for sources in transfer_map.values())
        
        logger.info(f'\n{Colors.RED.value}ALERT!{Colors.RESET.value}')
        logger.info('This action cannot be undone.')
        logger.info(f'Do you want to proceed with transferring {source_count} account(s)? [y/n]: ')
        answer = input().strip().lower()
        return answer == 'y'
    
    def _lock_source_users(self,
                          auth: keeper_auth.KeeperAuth,
                          transfer_map: Dict,
                          user_lookup: Dict):
        """Lock source users before transfer
        """
        sources = set()
        for target in transfer_map:
            sources.update(transfer_map[target])
        
        lock_requests = [
            {
                'command': 'enterprise_user_lock',
                'enterprise_user_id': user_lookup[email]['enterprise_user_id'],
                'lock': 'locked'
            }
            for email in sources
            if user_lookup[email].get('lock', UserLockState.UNLOCKED.value) != UserLockState.LOCKED.value
        ]
        
        if lock_requests:
            logger.info('Locking active users.')
            auth.execute_batch(lock_requests)
    
    def _load_target_keys(self,
                         auth: keeper_auth.KeeperAuth,
                         transfer_map: Dict) -> Dict:
        """Load public keys for all target users
        """
        target_users = list(transfer_map.keys())
        
        logger.info(f'Loading public keys for {len(target_users)} target user(s)...')
        
        auth.load_user_public_keys(target_users, send_invites=False)
        
        # Collect loaded keys
        target_keys = {}
        for target_user in target_users:
            user_keys = auth.get_user_keys(target_user)
            if user_keys:
                target_keys[target_user] = user_keys
                logger.debug(f'Loaded keys for {target_user}')
            else:
                logger.warning(f'Failed to get public key for "{target_user}". Transfer will be skipped.')
                del transfer_map[target_user]
        
        return target_keys
    
    def _execute_transfers(self,
                          context: KeeperParams,
                          transfer_map: Dict,
                          target_keys: Dict,
                          user_lookup: Dict):
                          
        transfer_manager = AccountTransferManager(
            context.enterprise_loader,
            context.auth
        )
        
        total_transfers = sum(len(sources) for sources in transfer_map.values())
        completed = 0
        failed = 0
        
        logger.debug(f'Transfer map contents: {dict(transfer_map)}')
        
        for target_user, source_users in transfer_map.items():
            if target_user not in target_keys:
                logger.warning(f'Skipping transfers to {target_user} (no public key)')
                failed += len(source_users)
                continue
            
            for source_user in source_users:
                try:
                    logger.info(f'[{completed+1}/{total_transfers}] Transferring {source_user} to {target_user}...')
                    
                    result = transfer_manager.transfer_account(
                        source_user,
                        target_user,
                        target_keys[target_user]
                    )
                    
                    if result.success:
                        completed += 1
                        logger.info(f'{source_user}: Account transferred successfully')
                        
                        if result.records_transferred > 0:
                            logger.info(f'Records: {result.records_transferred}')
                        if result.shared_folders_transferred > 0:
                            logger.info(f'Shared Folders: {result.shared_folders_transferred}')
                        if result.teams_transferred > 0:
                            logger.info(f'Teams: {result.teams_transferred}')
                        if result.user_folders_transferred > 0:
                            logger.info(f' User Folders: {result.user_folders_transferred}')
                        
                        # Show warnings for corrupted items
                        if result.corrupted_records > 0:
                            logger.warning(f'Corrupted records skipped: {result.corrupted_records}')
                        if result.corrupted_shared_folders > 0:
                            logger.warning(f'Corrupted shared folders skipped: {result.corrupted_shared_folders}')
                        if result.corrupted_teams > 0:
                            logger.warning(f'Corrupted teams skipped: {result.corrupted_teams}')
                        if result.corrupted_user_folders > 0:
                            logger.warning(f'Corrupted user folders skipped: {result.corrupted_user_folders}')
                    
                except Exception as e:
                    failed += 1
                    logger.error(f'Failed to transfer {source_user}: {e}')
                    # Unlock source user if transfer fails
                    self._unlock_source_users(context.auth, source_user, user_lookup)
        
        if failed > 0:
            logger.error(f'Failed transfers: {failed}')

    def _unlock_source_users(self,
                            auth: keeper_auth.KeeperAuth,
                            source_user: str,
                            user_lookup: Dict):
        """Unlock source user if transfer fails
        """
        if source_user not in user_lookup:
            logger.warning(f'Cannot unlock {source_user}: user not found in lookup')
            return
        
        user_data = user_lookup[source_user]
        enterprise_user_id = user_data.get('enterprise_user_id')
        
        if not enterprise_user_id:
            logger.warning(f'Cannot unlock {source_user}: enterprise_user_id not found')
            return
        
        unlock_requests = [
            {
                'command': 'enterprise_user_lock',
                'enterprise_user_id': enterprise_user_id,
                'lock': 'unlocked'
            }
        ]
        
        logger.info(f'Unlocking {source_user}...')
        auth.execute_batch(unlock_requests)