import argparse
import json
import re
from urllib.parse import urlunparse
from typing import Optional, List, Tuple

from . import base, enterprise_utils
from .. import api, constants
from ..params import KeeperParams
from keepersdk import crypto, utils, generator
from keepersdk.proto import enterprise_pb2
from keepersdk.vault import vault_record, record_management, record_facades
from .share_management import OneTimeShareCreateCommand


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

    def _resolve_node(
        self,
        context: KeeperParams,
        node_name: Optional[str]
    ) -> Tuple[int, List]:
        """
        Resolve the node for user creation.
        """
        if not node_name:
            return (
                context.enterprise_data.root_node.node_id,
                [context.enterprise_data.root_node]
            )
        
        node = enterprise_utils.NodeUtils.resolve_single_node(
            context.enterprise_data, node_name
        )

        return node.node_id, [node]

    def _validate_email(self, email: str) -> bool:
        """
        Validate email format.
        """
        if not email:
            self.logger.warning('Email parameter is required.')
            return False
        
        email_pattern = re.compile(constants.EMAIL_PATTERN)
        if not email_pattern.match(email):
            self.logger.warning(
                '"%s" appears not a valid email address. Skipping.',
                email
            )
            return False
        
        return True

    def _create_provision_request(
        self,
        context: KeeperParams,
        email: str,
        displayname: str,
        node_id: int
    ) -> Tuple:
        """
        Create and populate the user provision request.
        """
        tree_key = context.enterprise_data.enterprise_info.tree_key
        
        rq = enterprise_pb2.EnterpriseUsersProvisionRequest()  # type: ignore[attr-defined]  # noqa: E501
        rq.clientVersion = context.auth.keeper_endpoint.client_version
        
        data = {'displayname': displayname or email}
        user_data = json.dumps(data).encode('utf-8')
        user_password = generator.KeeperPasswordGenerator(
            length=20
        ).generate()
        user_data_key = utils.generate_aes_key()
        enterprise_user_id = context.enterprise_loader.get_enterprise_id()
        
        user_rq = enterprise_pb2.EnterpriseUsersProvision()  # type: ignore[attr-defined]  # noqa: E501
        user_rq.enterpriseUserId = enterprise_user_id
        user_rq.username = email
        user_rq.nodeId = node_id
        user_rq.encryptedData = utils.base64_url_encode(
            crypto.encrypt_aes_v1(user_data, tree_key)
        )
        user_rq.keyType = enterprise_pb2.ENCRYPTED_BY_DATA_KEY  # type: ignore[attr-defined]  # noqa: E501
        
        enterprise_ec_key = (
            context.enterprise_data.enterprise_info.ec_public_key
        )
        if not enterprise_ec_key:
            enterprise_ec_key = crypto.load_ec_public_key(
                utils.base64_url_decode(
                    context.auth.auth_context.enterprise_ec_public_key
                )
            )
        
        user_rq.enterpriseUsersDataKey = crypto.encrypt_ec(
            user_data_key, enterprise_ec_key
        )
        user_rq.authVerifier = utils.create_auth_verifier(
            user_password,
            crypto.get_random_bytes(16),
            constants.PBKDF2_ITERATIONS
        )
        user_rq.encryptionParams = utils.create_encryption_params(
            user_password,
            crypto.get_random_bytes(16),
            constants.PBKDF2_ITERATIONS,
            user_data_key
        )
        
        if not context.auth.auth_context.forbid_rsa:
            rsa_private_key, rsa_public_key = crypto.generate_rsa_key()
            rsa_private = crypto.unload_rsa_private_key(rsa_private_key)
            rsa_public = crypto.unload_rsa_public_key(rsa_public_key)
            user_rq.rsaPublicKey = rsa_public
            user_rq.rsaEncryptedPrivateKey = crypto.encrypt_aes_v1(
                rsa_private, user_data_key
            )
        
        ec_private_key, ec_public_key = crypto.generate_ec_key()
        ec_private = crypto.unload_ec_private_key(ec_private_key)
        ec_public = crypto.unload_ec_public_key(ec_public_key)
        user_rq.eccPublicKey = ec_public
        user_rq.eccEncryptedPrivateKey = crypto.encrypt_aes_v2(
            ec_private, user_data_key
        )
        
        user_rq.encryptedDeviceToken = (
            context.auth.auth_context.device_token
        )
        user_rq.encryptedClientKey = crypto.encrypt_aes_v1(
            utils.generate_aes_key(), user_data_key
        )
        
        rq.users.append(user_rq)
        return rq, user_password

    def _provision_user(
        self,
        context: KeeperParams,
        provision_request,
        email: str
    ) -> None:
        """
        Execute the user provision request.
        """
        rs = context.auth.execute_auth_rest(
            'enterprise/enterprise_user_provision',
            provision_request,
            response_type=enterprise_pb2.EnterpriseUsersProvisionResponse  # type: ignore[attr-defined]  # noqa: E501
        )
        
        for user_rs in rs.results:
            if user_rs.code == "exists":
                raise base.CommandError(
                    f'User "{email}" already exists'
                )
            if user_rs.code and user_rs.code not in ['success', 'ok']:
                doc_url = (
                    'https://docs.keeper.io/enterprise-guide/'
                    'user-and-team-provisioning/email-auto-provisioning'
                )
                raise base.CommandError(
                    f'Failed to auto-create account "{email}".\n'
                    'Creating user accounts without email verification is '
                    'only permitted on reserved domains.\n'
                    'To reserve a domain please contact Keeper support. '
                    f'Learn more about domain reservation here:\n{doc_url}'
                )

    def _create_password_record(
        self,
        context: KeeperParams,
        email: str,
        user_password: str,
        folder_name: Optional[str]
    ) -> vault_record.TypedRecord:
        """
        Create a vault record with user credentials.
        """
        folder_uid: Optional[str] = None
        if folder_name:
            folder = context.vault.vault_data.get_folder(folder_name)
            if folder:
                folder_uid = folder.folder_uid
            else:
                self.logger.warning(
                    'Folder "%s" not found. Using root folder.',
                    folder_name
                )
        
        keeper_url = urlunparse((
            'https',
            context.server,
            '/vault',
            None,
            None,
            f'email/{email}'
        ))
        
        record = vault_record.TypedRecord()
        login_facade = record_facades.LoginRecordFacade()
        login_facade.record = record
        login_facade.title = f'Keeper Account: {email}'
        login_facade.login = email
        login_facade.password = user_password
        login_facade.url = keeper_url
        login_facade.notes = (
            'The user is required to change their Master Password '
            'upon login.'
        )
        
        record_management.add_record_to_folder(
            context.vault, record, folder_uid=folder_uid
        )
        context.vault.sync_down()
        
        return record

    def _add_one_time_share(
        self,
        context: KeeperParams,
        record: vault_record.TypedRecord,
        email: str
    ) -> Optional[str]:
        """
        Create and add one-time share link to the record
        """
        ots_command = OneTimeShareCreateCommand()
        ots_url = ots_command.execute(
            context,
            record=record.record_uid,
            share_name=f'{email}: Master Password',
            expire='7d'
        )
        
        if ots_url:
            ots_field = vault_record.TypedField()
            ots_field.type = 'url'
            ots_field.label = 'One-Time Share'
            ots_field.value = [ots_url]
            record.custom.append(ots_field)
            record_management.update_record(context.vault, record)
            context.vault.sync_down()
        
        return ots_url

    def _print_results(
        self,
        email: str,
        displayname: str,
        user_password: str,
        keeper_url: str,
        notes: str,
        nodes: List,
        ots_url: Optional[str],
        verbose: bool
    ) -> None:
        """
        Print the results of user creation.
        """
        if verbose:
            print(
                f'The account {email} has been created. '
                'Login details below:'
            )
            print(f'{"Vault Login URL:":>24s} {keeper_url}')
            print(f'{"Email:":>24s} {email}')
            if displayname:
                print(f'{"Name:":>24s} {displayname}')
            if nodes and nodes[0] and nodes[0].name:
                print(f'{"Node:":>24s} {nodes[0].name}')
            print(f'{"Master Password:":>24s} {user_password}')
            if ots_url:
                print(f'{"One-Time Share Link:":>24s} {ots_url}')
            print(f'{"Note:":>24s} {notes}')
        else:
            self.logger.info(
                'User "%s" credentials are stored to record "%s"',
                email,
                f'Keeper Account: {email}'
            )

    def execute(self, context: KeeperParams, **kwargs):
        """
        Execute the create user command.
        """
        assert context.enterprise_data is not None
        assert context.vault is not None
        assert context.auth is not None
        assert context.enterprise_loader is not None
        
        email = kwargs.get('email')
        displayname = kwargs.get('full_name', '')
        node_name = kwargs.get('node')
        folder_name = kwargs.get('folder')
        verbose = kwargs.get('verbose', False)
        
        if not self._validate_email(email):
            return None
        
        node_id, nodes = self._resolve_node(context, node_name)

        if len(nodes) == 0:
            self.logger.warning('Node \"%s\" not found', node_name)
            return None
        if len(nodes) > 1:
            self.logger.warning('More than one nodes \"%s\" are found', node_name)
            return None
        
        provision_request, user_password = self._create_provision_request(
            context, email, displayname, node_id
        )
        
        self._provision_user(context, provision_request, email)
        
        context.enterprise_loader.load()
        
        record = self._create_password_record(
            context, email, user_password, folder_name
        )
        
        ots_url = self._add_one_time_share(context, record, email)
        
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
        
        self._print_results(
            email, displayname, user_password, keeper_url,
            notes, nodes, ots_url, verbose
        )
        
        return record.record_uid
