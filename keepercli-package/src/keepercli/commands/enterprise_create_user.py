import argparse
from typing import Optional
from urllib.parse import urlunparse

from . import base
from .. import api
from ..params import KeeperParams
from keepersdk.vault import vault_record
from keepersdk.enterprise.enterprise_user_management import EnterpriseUserManager, CreateUserResponse
from .share_management import OneTimeShareCreateCommand

# Constants
DEFAULT_ONE_TIME_SHARE_EXPIRY = '7d'
ONE_TIME_SHARE_LABEL = 'One-Time Share'
ONE_TIME_SHARE_FIELD_TYPE = 'url'
VAULT_URL_PATH = '/vault'
PASSWORD_CHANGE_NOTE = (
    'The user is required to change their Master Password '
    'upon login.'
)

# Logging format constants
LOG_FORMAT_VERBOSE_HEADER = 'The account {} has been created. Login details below:'
LOG_FORMAT_VERBOSE_SUCCESS = 'User "{}" has been created with ID {}'
LOG_FORMAT_FIELD_WIDTH = 24

logger = api.get_logger()

class CreateEnterpriseUserCommand(base.ArgparseCommand):
    """Create an enterprise user command."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='create-user',
            description='Create an enterprise user.'
        )
        CreateEnterpriseUserCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add command line arguments to parser."""
        parser.add_argument('email', help='User email')
        parser.add_argument(
            '--name', dest='full_name', action='store',
            help='user name'
        )
        parser.add_argument(
            '--node', dest='node', action='store',
            help='node name or node ID'
        )
        parser.add_argument(
            '--folder', dest='folder', action='store',
            help='folder name or UID to store password record'
        )
        parser.add_argument(
            '-v', '--verbose', dest='verbose', action='store_true',
            help='print verbose information'
        )

    def _create_enterprise_user_manager(self, context: KeeperParams) -> EnterpriseUserManager:
        """
        Create an EnterpriseUserManager instance from KeeperParams context.
        """
        return EnterpriseUserManager(
            loader=context.enterprise_loader,
            auth_context=context.auth
        )

    def _add_one_time_share(
        self,
        context: KeeperParams,
        record_uid: str,
        email: str
    ) -> Optional[str]:
        """
        Create and add one-time share link to the record.
        
        Args:
            context: Keeper parameters context
            record_uid: UID of the record to share
            email: Email address for the share name
            
        Returns:
            One-time share URL if successful, None otherwise
        """
        try:
            if not self._validate_record_exists(context, record_uid):
                return None
            
            ots_url = self._create_one_time_share_url(context, record_uid, email)
            if ots_url:
                self._add_share_url_to_record(context, record_uid, ots_url)
            
            return ots_url
        except Exception as e:
            logger.warning(f"Could not create one-time share: {e}")
            return None

    def _validate_record_exists(self, context: KeeperParams, record_uid: str) -> bool:
        """Validate that the record exists in the vault."""
        record_data = context.vault.vault_data.get_record(record_uid)
        if not record_data:
            logger.warning(f"Could not load record {record_uid} for one-time share")
            return False
        return True

    def _create_one_time_share_url(
        self, 
        context: KeeperParams, 
        record_uid: str, 
        email: str
    ) -> Optional[str]:
        """Create one-time share URL for the record."""
        ots_command = OneTimeShareCreateCommand()
        return ots_command.execute(
            context,
            record=record_uid,
            share_name=f'{email}: Master Password',
            expire=DEFAULT_ONE_TIME_SHARE_EXPIRY
        )

    def _add_share_url_to_record(
        self, 
        context: KeeperParams, 
        record_uid: str, 
        ots_url: str
    ) -> None:
        """Add one-time share URL as a custom field to the record."""
        from keepersdk.vault import record_management
        
        full_record = context.vault.vault_data.load_record(record_uid)
        
        if isinstance(full_record, vault_record.TypedRecord):
            ots_field = vault_record.TypedField()
            ots_field.type = ONE_TIME_SHARE_FIELD_TYPE
            ots_field.label = ONE_TIME_SHARE_LABEL
            ots_field.value = [ots_url]
            full_record.custom.append(ots_field)
            record_management.update_record(context.vault, full_record)
            context.vault.sync_down()

    def _log_results(
        self,
        result: CreateUserResponse,
        displayname: str,
        keeper_url: str,
        notes: str,
        verbose: bool
    ) -> None:
        """
        Log the results of user creation.
        
        Args:
            result: User creation response
            displayname: User display name
            keeper_url: Keeper vault URL
            notes: Additional notes to display
            verbose: Whether to show verbose output
        """
        if verbose:
            self._log_verbose_results(result, displayname, keeper_url, notes)
        else:
            self._log_simple_results(result)

    def _log_verbose_results(
        self, 
        result: CreateUserResponse, 
        displayname: str, 
        keeper_url: str, 
        notes: str
    ) -> None:
        """Log verbose user creation results."""
        logger.info(LOG_FORMAT_VERBOSE_HEADER.format(result.email))
        
        field_width = LOG_FORMAT_FIELD_WIDTH
        logger.info(f'{"Vault Login URL:":>{field_width}s} {keeper_url}')
        logger.info(f'{"Email:":>{field_width}s} {result.email}')
        
        if displayname:
            logger.info(f'{"Name:":>{field_width}s} {displayname}')
        if result.node_id:
            logger.info(f'{"Node ID:":>{field_width}s} {result.node_id}')
            
        logger.info(f'{"Master Password:":>{field_width}s} {result.generated_password}')
        logger.info(f'{"Note:":>{field_width}s} {notes}')

    def _log_simple_results(self, result: CreateUserResponse) -> None:
        """Log simple user creation results."""
        logger.info(
            LOG_FORMAT_VERBOSE_SUCCESS.format(
                result.email, 
                result.enterprise_user_id
            )
        )

    def execute(self, context: KeeperParams, **kwargs):
        """
        Execute the create user command.
        
        Args:
            context: Keeper parameters context
            **kwargs: Command line arguments
            
        Returns:
            Enterprise user ID if successful, None otherwise
            
        Raises:
            CommandError: If user creation fails
        """
        self._validate_context(context)
        
        email = kwargs.get('email')
        displayname = kwargs.get('full_name', '')
        node_name = kwargs.get('node')
        verbose = kwargs.get('verbose', False)
        
        try:
            result = self._create_user(context, email, displayname, node_name)
            keeper_url = self._build_keeper_url(context.server, email)
            
            self._log_results(
                result, displayname, keeper_url, PASSWORD_CHANGE_NOTE, verbose
            )
            
            return result.enterprise_user_id
            
        except ValueError as e:
            logger.error(str(e))
            return None
        except Exception as e:
            if "already exists" in str(e):
                raise base.CommandError(str(e))
            else:
                raise base.CommandError(f"Failed to create user: {str(e)}")

    def _validate_context(self, context: KeeperParams) -> None:
        """Validate that required context data is available."""
        assert context.enterprise_data is not None
        assert context.auth is not None

    def _create_user(
        self, 
        context: KeeperParams, 
        email: str, 
        displayname: str, 
        node_name: Optional[str]
    ) -> CreateUserResponse:
        """Create the enterprise user."""
        user_manager = self._create_enterprise_user_manager(context)
        
        from keepersdk.enterprise.enterprise_user_management import CreateUserRequest
        request = CreateUserRequest(
            email=email,
            display_name=displayname,
            node_name=node_name
        )
        return user_manager.create_user(request)

    def _build_keeper_url(self, server: str, email: str) -> str:
        """Build the Keeper vault URL for the user."""
        return urlunparse((
            'https',
            server,
            VAULT_URL_PATH,
            None,
            None,
            f'email/{email}'
        ))
