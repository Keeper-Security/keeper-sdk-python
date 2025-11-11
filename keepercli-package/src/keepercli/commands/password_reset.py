"""
Password reset command for Keeper CLI.

This module provides the CLI interface for resetting or managing master passwords
for both regular and SSO accounts.
"""

import argparse
import getpass
import logging
import re
from typing import Optional

from keepersdk import crypto, utils, errors
from keepersdk.proto import APIRequest_pb2, enterprise_pb2
from . import base
from .. import api, constants
from ..params import KeeperParams


logger = api.get_logger()


# Create the argument parser for reset password command
reset_password_parser = argparse.ArgumentParser(
    prog='reset-password', 
    description='Reset or manage master password for Keeper account'
)
reset_password_parser.add_argument(
    '--current-password', '-cp',
    dest='current_password',
    action='store',
    help='Current master password (will be prompted if not provided)'
)
reset_password_parser.add_argument(
    '--new-password', '-np',
    dest='new_password', 
    action='store',
    help='New master password (will be prompted if not provided)'
)
reset_password_parser.add_argument(
    '--delete-alternate', '-da',
    dest='delete_alternate',
    action='store_true',
    help='Delete SSO alternate password instead of changing it'
)


class ResetPasswordCommand(base.ArgparseCommand):
    """Command for resetting master passwords for regular and SSO accounts."""

    def __init__(self):
        """Initialize the reset password command."""
        super().__init__(reset_password_parser)

    def get_parser(self):
        """Get the argument parser for this command."""
        return reset_password_parser

    def execute(self, context: KeeperParams, **kwargs):
        """Execute the password reset command."""
        current_password = kwargs.get('current_password')
        is_sso_user = context.settings.get('sso_user', False)

        if is_sso_user:
            allow_alternate_passwords = False
            if 'booleans' in context.enforcements:
                allow_alternate_passwords = next((x.get('value') for x in context.enforcements['booleans']
                                                  if x.get('key') == 'allow_alternate_passwords'), False)

            if not allow_alternate_passwords:
                logging.warning('You do not have the required privilege to perform this operation.')
                return

        try:
            current_salt = context.auth.execute_auth_rest(
                'authentication/get_salt_and_iterations',
                None,
                response_type=APIRequest_pb2.Salt
            )
        except errors.KeeperApiError as kae:
            if is_sso_user and kae.result_code == 'doesnt_exist':
                current_salt = None
            else:
                raise kae

        is_delete_alternate = kwargs.get('delete_alternate')
        if is_delete_alternate:
            if is_sso_user:
                logging.info('Deleting SSO Master Password for "%s"', context.user)
            else:
                logging.warning('"%s" is not SSO account', context.user)
                return
        else:
            if is_sso_user:
                logging.info('%s SSO Master Password for "%s"',
                             'Changing' if current_salt else 'Setting', context.user)
            else:
                logging.info('Changing Master Password for "%s"', context.user)

        if current_salt:
            # Validate current password
            if not current_password:
                current_password = getpass.getpass(prompt='Current Master Password: ').strip()

            auth_hash = crypto.derive_keyhash_v1(current_password, current_salt.salt, current_salt.iterations)

            rq = APIRequest_pb2.MasterPasswordReentryRequest()
            rq.pbkdf2Password = utils.base64_url_encode(auth_hash)
            rq.action = APIRequest_pb2.UNMASK

            try:
                rs = context.auth.execute_auth_rest(
                    'authentication/validate_master_password',
                    rq,
                    response_type=APIRequest_pb2.MasterPasswordReentryResponse,
                    payload_version=1
                )
                if rs.status != APIRequest_pb2.MP_SUCCESS:
                    logging.info('Failed to change password')
                    return
            except:
                logging.warning('Current password incorrect')
                return
        else:
            current_password = ''

        if is_delete_alternate:
            if current_salt:
                uid_rq = APIRequest_pb2.UidRequest()
                uid_rq.uid.append(current_salt.uid)

                context.auth.execute_auth_rest('authentication/delete_v2_alternate_password', uid_rq)
                logging.info('SSO Master Password has been deleted')
            else:
                logging.info('SSO Master password is not found')
            return

        new_password = kwargs.get('new_password')
        if not new_password:
            password1 = getpass.getpass(prompt='{0:>24}: '.format('New Password')).strip()
            password2 = getpass.getpass(prompt='{0:>24}: '.format('Re-enter New Password')).strip()
            print('')

            if password1 != password2:
                logging.warning('New password does not match')
                return

            if current_password and password1 == current_password:
                logging.warning('Please choose a different password')
                return

            new_password = password1

        # Validate password rules
        rules_rq = enterprise_pb2.DomainPasswordRulesRequest()
        rules_rq.username = context.user

        rules_rs = context.auth.execute_auth_rest(
            'authentication/get_domain_password_rules',
            rules_rq,
            response_type=APIRequest_pb2.NewUserMinimumParams
        )

        failed_rules = []
        for i in range(len(rules_rs.passwordMatchRegex)):
            rule = rules_rs.passwordMatchRegex[i]
            is_match = re.match(rule, new_password)
            if not is_match:
                failed_rules.append(rules_rs.passwordMatchDescription[i])

        if failed_rules:
            logging.warning('Password rules:\n%s', '\n'.join((f'  {x}' for x in failed_rules)))
            return

        # Check password strength using breach watch or internal scoring
        if hasattr(context, 'breach_watch') and context.breach_watch:
            euids = []
            for result in context.breach_watch.scan_passwords(context, [new_password]):
                if result[1].euid:
                    euids.append(result[1].euid)
                logging.info('Breachwatch password scan result: %s', 'WEAK' if result[1].breachDetected else 'GOOD')

            if euids:
                context.breach_watch.delete_euids(context, euids)
        else:
            score = utils.password_score(new_password)
            logging.info('Password strength: %s', 'WEAK' if score < 40 else 'FAIR' if score < 60 else 'MEDIUM' if score < 80 else 'STRONG')

        # Set up encryption parameters
        iterations = current_salt.iterations if current_salt else constants.PBKDF2_ITERATIONS
        iterations = max(iterations, constants.PBKDF2_ITERATIONS)

        auth_salt = crypto.get_random_bytes(16)

        if is_sso_user:
            # Handle SSO user alternate password
            ap_rq = APIRequest_pb2.UserAuthRequest()
            ap_rq.uid = current_salt.uid if current_salt else crypto.get_random_bytes(16)
            ap_rq.salt = auth_salt
            ap_rq.iterations = iterations
            ap_rq.authHash = crypto.derive_keyhash_v1(new_password, auth_salt, iterations)

            key = crypto.derive_keyhash_v2('data_key', new_password, auth_salt, iterations)
            ap_rq.encryptedDataKey = crypto.encrypt_aes_v2(context.auth.auth_context.data_key, key)
            ap_rq.encryptedClientKey = crypto.encrypt_aes_v2(context.auth.auth_context.client_key, key)

            ap_rq.loginType = APIRequest_pb2.ALTERNATE
            ap_rq.name = current_salt.name if current_salt else 'alternate'

            context.auth.execute_auth_rest('authentication/set_v2_alternate_password', ap_rq)
            logging.info(f'SSO Master Password has been {"changed" if current_salt else "set"}')

        else:
            # Handle regular user password change
            auth_verifier = utils.create_auth_verifier(new_password, auth_salt, iterations)

            data_salt = crypto.get_random_bytes(16)
            encryption_params = utils.create_encryption_params(
                new_password, data_salt, iterations, context.auth.auth_context.data_key
            )

            mp_rq = {
                'command': 'change_master_password',
                'auth_verifier': utils.base64_url_encode(auth_verifier),
                'encryption_params': utils.base64_url_encode(encryption_params)
            }

            api.communicate(context, mp_rq)
            logging.info('Master Password has been changed')
