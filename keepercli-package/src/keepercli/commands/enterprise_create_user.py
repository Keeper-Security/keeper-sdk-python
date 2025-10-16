import argparse
from typing import Optional
from urllib.parse import urlunparse

from . import base, enterprise_utils
from .. import api
from ..params import KeeperParams
from keepersdk.vault import vault_record
from .share_management import OneTimeShareCreateCommand

# Import SDK enterprise user management functionality
try:
    from keepersdk.enterprise.enterprise_user_management import EnterpriseUserManager, CreateUserResponse
except ImportError:
    # Fallback if the module is not available
    EnterpriseUserManager = None
    CreateUserResponse = None


class CreateEnterpriseUserCommand(base.ArgparseCommand):
    """Create an enterprise user command."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='create-user',
            description='Create an enterprise user.'
        )
        CreateEnterpriseUserCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
        self.logger = api.get_logger()

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
        Create and add one-time share link to the record
        """
        try:
            # Load the actual record from vault
            record_data = context.vault.vault_data.get_record(record_uid)
            if not record_data:
                self.logger.warning(f"Could not load record {record_uid} for one-time share")
                return None
            
            ots_command = OneTimeShareCreateCommand()
            ots_url = ots_command.execute(
                context,
                record=record_uid,  # Pass the record UID directly as it can be resolved
                share_name=f'{email}: Master Password',
                expire='7d'
            )
            
            if ots_url:
                # Load the full record object to add the one-time share field
                from keepersdk.vault import record_management
                full_record = context.vault.vault_data.load_record(record_uid)
                
                # Create and add the one-time share field
                if isinstance(full_record, vault_record.TypedRecord):
                    ots_field = vault_record.TypedField()
                    ots_field.type = 'url'
                    ots_field.label = 'One-Time Share'
                    ots_field.value = [ots_url]
                    full_record.custom.append(ots_field)
                    record_management.update_record(context.vault, full_record)
                    context.vault.sync_down()
            
            return ots_url
        except Exception as e:
            self.logger.warning(f"Could not create one-time share: {e}")
            return None

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
        """
        if verbose:
            self.logger.info(
                f'The account {result.email} has been created. '
                'Login details below:'
            )
            self.logger.info(f'{"Vault Login URL:":>24s} {keeper_url}')
            self.logger.info(f'{"Email:":>24s} {result.email}')
            if displayname:
                self.logger.info(f'{"Name:":>24s} {displayname}')
            if result.node_id:
                self.logger.info(f'{"Node ID:":>24s} {result.node_id}')
            self.logger.info(f'{"Master Password:":>24s} {result.generated_password}')
            # Note: One-time share functionality temporarily disabled
            # if ots_url:
            #     self.logger.info(f'{"One-Time Share Link:":>24s} {ots_url}')
            self.logger.info(f'{"Note:":>24s} {notes}')
        else:
            self.logger.info(
                'User "%s" has been created with ID %d',
                result.email,
                result.enterprise_user_id
            )

    def execute(self, context: KeeperParams, **kwargs):
        """
        Execute the create user command.
        """
        assert context.enterprise_data is not None
        assert context.auth is not None
        
        email = kwargs.get('email')
        displayname = kwargs.get('full_name', '')
        node_name = kwargs.get('node')
        folder_name = kwargs.get('folder')
        verbose = kwargs.get('verbose', False)
        
        # Check if SDK functionality is available
        if EnterpriseUserManager is None:
            raise base.CommandError(
                "SDK enterprise user management functionality not available. "
                "Please ensure keepersdk.enterprise.enterprise_user_management is properly installed."
            )
        
        try:
            # Create the SDK user manager
            user_manager = self._create_enterprise_user_manager(context)
            
            # Create the user using SDK functionality
            from keepersdk.enterprise.enterprise_user_management import CreateUserRequest
            request = CreateUserRequest(
                email=email,
                display_name=displayname,
                node_name=node_name  # Pass node name for resolution in SDK
            )
            result = user_manager.create_user(request)
            
            # Note: One-time share functionality temporarily disabled
            # The new SDK approach doesn't automatically create vault records
            # TODO: Implement record creation and one-time share if needed
            
            # Build keeper URL for display
            keeper_url = urlunparse((
                'https',
                context.server,
                '/vault',
                None,
                None,
                f'email/{email}'
            ))
            
            notes = (
                'The user is required to change their Master Password '
                'upon login.'
            )
            
            # Log results
            self._log_results(
                result, displayname, keeper_url, notes, verbose
            )
            
            return result.enterprise_user_id
            
        except ValueError as e:
            self.logger.error(str(e))
            return None
        except Exception as e:
            if "already exists" in str(e):
                raise base.CommandError(str(e))
            else:
                raise base.CommandError(
                    f"Failed to create user: {str(e)}"
                )
