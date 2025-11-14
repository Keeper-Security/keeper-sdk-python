import argparse
import datetime
import re
from typing import Tuple, Optional, List, Any

from keepersdk import crypto, utils
from keepersdk.authentication import keeper_auth  
from keepersdk.proto import AccountSummary_pb2, APIRequest_pb2
from keepersdk.vault import vault_online
from . import base
from .. import params, login, api
from ..helpers import parse_utils, timeout_utils, report_utils

# Reset Password Command Constants
RESET_PASSWORD_NOT_LOGGED_IN = 'Not logged in'
RESET_PASSWORD_SSO_NOT_IMPLEMENTED = 'SSO alternate password deletion is not yet implemented'
RESET_PASSWORD_SUCCESS = 'Master Password has been changed successfully'
RESET_PASSWORD_CANCELLED = 'Password change was cancelled or failed'
RESET_PASSWORD_ERROR = 'Error changing password: {}'
RESET_PASSWORD_CHANGING = 'Changing Master Password for "{}"'
RESET_PASSWORD_CURRENT_INCORRECT = 'Current password incorrect'
RESET_PASSWORD_BREACHWATCH_SCAN = 'Breachwatch: 1 passwords to scan'
RESET_PASSWORD_BREACHWATCH_RESULT = 'Breachwatch password scan result: {}'


logger = api.get_logger()


class LoginCommand(base.ArgparseCommand):
    login_parser = argparse.ArgumentParser(prog='login', description='Login to Keeper')
    login_parser.add_argument('--sso-password', dest='sso_password', action='store_true',
                              help='force master password for SSO accounts')
    login_parser.add_argument('--resume-session', dest='resume_session', action='store_true',
                              help='resumes current login session')
    login_parser.add_argument('-p', '--pass', dest='password', action='store', help='master password')
    login_parser.add_argument('email', metavar='EMAIL',  help='account email')

    def __init__(self):
        super().__init__(LoginCommand.login_parser)

    def execute(self, context: params.KeeperParams, **kwargs):
        username = kwargs.get('email') or ''
        password = kwargs.get('password') or ''
        resume_session = kwargs.get('resume_session') is True
        auth = login.LoginFlow.login(
            context.keeper_config, username=username, password=password, server=context.keeper_config.server,
            resume_session=resume_session, sso_master_password=kwargs.get('sso_password') is True)
        if auth is None:
            raise base.CommandError("Login failed")
        context.set_auth(auth)
        # TODO check enforcements


class LogoutCommand(base.ArgparseCommand):
    logout_parser = argparse.ArgumentParser(prog='logout', description='Logout from Keeper')

    def __init__(self):
        super().__init__(LogoutCommand.logout_parser)

    def execute(self, context: params.KeeperParams, **kwargs):
        login.logout(context)


class ThisDeviceCommand(base.ArgparseCommand):
    this_device_available_command_verbs = ['rename', 'register', 'persistent-login', 'ip-auto-approve',
                                           'no-yubikey-pin', 'timeout']
    this_device_parser = argparse.ArgumentParser(prog='this-device',
                                                 description='Display and modify settings of the current device')
    this_device_parser.add_argument('ops', nargs='*',
                                    help="operation str: " + ", ".join(this_device_available_command_verbs))

    def __init__(self):
        super().__init__(ThisDeviceCommand.this_device_parser)

    def execute(self, context: params.KeeperParams, **kwargs):
        assert context.auth is not None
        logger = api.get_logger()
        ops = kwargs.get('ops')
        if not isinstance(ops, list):
            return
        if len(ops) == 0:
            ThisDeviceCommand.print_device_info(context)
            logger.info("\nAvailable sub-commands: %s", ', '.join(ThisDeviceCommand.this_device_available_command_verbs))
            return

        if len(ops) >= 1 and ops[0].lower() != 'register':
            if len(ops) == 1 and ops[0].lower() != 'register':
                logger.error("Must supply action and value. Available sub-commands: " + ", ".join(
                    ThisDeviceCommand.this_device_available_command_verbs))
                return

            if len(ops) != 2:
                logger.error("Must supply action and value. Available sub-commands: " + ", ".join(
                    ThisDeviceCommand.this_device_available_command_verbs))
                return

        action = ops[0].lower()

        if action == 'rename' or action == 'ren':
            value = ops[1]
            keeper_auth.rename_device(context.auth, value)
            logger.info(f'Successfully renamed device to {value}')

        elif action == 'register':
            is_device_registered = keeper_auth.register_data_key_for_device(context.auth)
            if is_device_registered:
                logger.info('Successfully registered device')
            else:
                logger.info('Device already registered')

        elif action == 'persistent_login' or action == 'persistent-login' or action == 'pl':
            if ThisDeviceCommand.is_persistent_login_disabled(context):
                logger.warning('"Stay Logged In" feature is restricted by Keeper Administrator')
                return

            value = ops[1]

            value_extracted = '1' if parse_utils.as_boolean(value) else '0'
            keeper_auth.set_user_setting(context.auth, 'persistent_login', value_extracted)
            msg = 'ENABLED' if value_extracted == '1' else 'DISABLED'
            logger.info(f'Successfully {msg} Persistent Login on this account')

            if value_extracted == '1':
                keeper_auth.register_data_key_for_device(context.auth)
                _, this_device = ThisDeviceCommand.get_account_summary_and_this_device(context)

                if this_device and not this_device.encryptedDataKeyPresent:
                    logger.warning('\tThis device is not registered. '
                                   'To register, run command `this-device register`')

        elif action == 'ip_auto_approve' or action == 'ip-auto-approve' or action == 'iaa':
            value = ops[1]

            value_extracted = '1' if parse_utils.as_boolean(value) else '0'
            msg = 'ENABLED' if value_extracted == '1' else 'DISABLED'
            # invert ip_auto_approve value before passing it to ip_disable_auto_approve
            value_extracted = '0' if value_extracted == '1' else '1' if value_extracted == '0' else value_extracted
            keeper_auth.set_user_setting(context.auth, 'ip_disable_auto_approve', value_extracted)
            logger.info(f'Successfully {msg} `ip_auto_approve`')

        elif action == 'no-yubikey-pin':
            value = ops[1]
            value_extracted = '1' if parse_utils.as_boolean(value) else '0'
            msg = 'ENABLED' if value_extracted == '0' else 'DISABLED'
            keeper_auth.set_user_setting(context.auth, 'security_keys_no_user_verify', value_extracted)
            logger.info(f'Successfully {msg} Security Key PIN verification')

        elif action == 'timeout' or action == 'to':
            value = ops[1]
            delta = timeout_utils.parse_timeout(value)
            timeout_in_minutes = delta.seconds // 60
            if timeout_in_minutes < 3:
                timeout_in_minutes = 0
            keeper_auth.set_user_setting(context.auth, 'logout_timer', str(timeout_in_minutes))
            display_value = 'default value' if delta == datetime.timedelta(0) else \
                timeout_utils.format_timeout(delta)
            logger.info('Successfully set "logout_timer" to %s.', display_value)

        else:
            commands = ', '.join(ThisDeviceCommand.this_device_available_command_verbs)
            raise base.CommandError(f'Unknown sub-command {action}. Available sub-commands: {commands}')

    @staticmethod
    def is_persistent_login_disabled(context: params.KeeperParams) -> bool:
        assert context.auth is not None
        enforcements = context.auth.auth_context.enforcements
        if enforcements and 'booleans' in enforcements:
            return next(
                (x['value'] for x in enforcements['booleans'] if x['key'] == 'restrict_persistent_login'), False)
        else:
            return False

    @staticmethod
    def get_account_summary_and_this_device(context: params.KeeperParams) \
            -> Tuple[AccountSummary_pb2.AccountSummaryElements, AccountSummary_pb2.DeviceInfo]:
        assert context.auth is not None
        acct_summary = keeper_auth.load_account_summary(context.auth)
        devices = acct_summary.devices
        current_device_token = context.auth.auth_context.device_token
        this_device = next((x for x in devices if x.encryptedDeviceToken == current_device_token), None)
        assert this_device is not None
        return acct_summary, this_device

    @staticmethod
    def print_device_info(context: params.KeeperParams):
        acct_summary, this_device = ThisDeviceCommand.get_account_summary_and_this_device(context)

        table: List[List[Any]] = list()
        table.append(['Device Name', this_device.deviceName])
        table.append(['Data Key Present', this_device.encryptedDataKeyPresent])
        table.append(['IP Auto Approve', not acct_summary.settings.ipDisableAutoApprove])
        restricted = next((x.value for x in acct_summary.Enforcements.booleans if x.key == 'restrict_persistent_login'), False)
        table.append(['Persistent Login', acct_summary.settings.persistentLogin and not restricted])

        if acct_summary.settings.logoutTimer > 0:
            device_timeout = datetime.timedelta(milliseconds=acct_summary.settings.logoutTimer)
        else:
            device_timeout = datetime.timedelta(hours=1)
        table.append(['Device Logout Timeout', timeout_utils.format_timeout(device_timeout)])

        logout_timeout = next((x.value for x in acct_summary.Enforcements.longs if x.key == 'logout_timer_desktop'), None)
        if logout_timeout:
            enterprise_timeout = datetime.timedelta(minutes=int(logout_timeout))
            table.append(['Enterprise Logout Timeout', timeout_utils.format_timeout(enterprise_timeout)])
            table.append(['Effective Logout Timeout', timeout_utils.format_timeout(min(enterprise_timeout, device_timeout))])

        table.append(['Is SSO User', acct_summary.settings.ssoUser])
        report_utils.dump_report_data(table, ('key', 'value'), no_header=True, right_align=(0,))


class WhoamiCommand(base.ArgparseCommand):
    whoami_parser = argparse.ArgumentParser(prog='whoami',
                                            description='Display information about the currently logged in user')
    whoami_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')

    def __init__(self):
        super().__init__(WhoamiCommand.whoami_parser)

    @staticmethod
    def get_data_center(hostname):
        if hostname.endswith('.eu'):
            data_center = 'EU'
        elif hostname.endswith('.com'):
            data_center = 'US'
        elif hostname.endswith('govcloud.keepersecurity.us'):
            data_center = 'US GOV'
        elif hostname.endswith('.au'):
            data_center = 'AU'
        else:
            data_center = hostname
        return data_center

    @staticmethod
    def get_environment(hostname: str) -> Optional[str]:
        if hostname:
            if hostname.startswith('dev.'):
                return 'DEV'
            elif hostname.startswith('qa.'):
                return 'QA'
            elif hostname.startswith('local.'):
                return 'LOCAL'

    def execute(self, context: params.KeeperParams, **kwargs):
        logger = api.get_logger()
        if context.auth:
            table: List[List[Any]] = list()
            table.append(['User', context.auth.auth_context.username])
            hostname = context.auth.keeper_endpoint.server
            table.append(['Server', hostname])
            table.append(['Data Center', WhoamiCommand.get_data_center(hostname)])
            environment = WhoamiCommand.get_environment(hostname)
            if environment:
                table.append(['Environment', environment])
            lic = context.auth.auth_context.license
            if lic:
                account_type = lic.get('accountType')
                if account_type == 2:
                    table.append(['Admin', context.auth.auth_context.is_enterprise_admin])
                account_type_name = 'Enterprise' if account_type == 2 else \
                    'Family Plan' if account_type == 1 else \
                        lic.get('productTypeName')

                table.append(['Account Type', account_type_name])
                table.append(['Renewal Date', lic.get('expirationDate')])
                if 'bytes_total' in lic:
                    storage_bytes = int(lic.get('bytesTotal', 0))  # note: int64 in protobuf in python produces string as opposed to an int or long.
                    storage_gb = storage_bytes >> 30
                    storage_bytes_used = lic.get('bytesUsed', 0)
                    table.append(['Storage Capacity', f'{storage_gb}GB'])

                    storage_usage = (int(storage_bytes_used) * 100 // storage_bytes) if storage_bytes != 0 else 0     # note: int64 in protobuf in python produces string  as opposed to an int or long.
                    table.append(['Usage', f'{storage_usage}%'])
                    table.append(['Storage Renewal Date', lic.get('storageExpirationDate')])
                table.append(['BreachWatch', lic.get('breachWatchEnabled')])
                if context.auth.auth_context.is_enterprise_admin:
                    table.append(['Reporting & Alerts', lic.get('auditAndReportingEnabled')])

            if kwargs.get('verbose', False):
                if context.vault:
                    table.append(['Records', context.vault.vault_data.record_count])
                    if context.vault.vault_data.shared_folder_count > 0:
                        table.append(['Shared Folders', context.vault.vault_data.shared_folder_count])
                    if context.vault.vault_data.team_count > 0:
                        table.append(['Teams', context.vault.vault_data.team_count])

            report_utils.dump_report_data(table, ('key', 'value'), no_header=True, right_align=(0,))
        else:
            logger.warning('Not logged in')


class ResetPasswordCommand(base.ArgparseCommand):
    """Command for resetting master password using LoginAPI."""
    
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='reset-password', 
            description='Reset master password for Keeper account'
        )
        parser.add_argument(
            '--delete-sso',
            dest='delete_sso',
            action='store_true',
            help='deletes SSO master password'
        )
        parser.add_argument(
            '--current', '-c',
            dest='current_password',
            metavar='CURRENT_PASSWORD',
            help='current password'
        )
        parser.add_argument(
            '--new', '-n',
            dest='new_password',
            metavar='NEW_PASSWORD',
            help='new password'
        )
        super().__init__(parser)

    def execute(self, context: params.KeeperParams, **kwargs):
        """Execute the password reset command."""
        
        if not self._validate_authentication(context):
            return
            
        if self._handle_sso_deletion(kwargs):
            return
        
        try:
            current_password = kwargs.get('current_password')
            new_password = kwargs.get('new_password')
            
            if current_password and new_password:
                self._change_password_non_interactive(context, current_password, new_password)
            else:
                self._change_password_interactive(context)
                
        except Exception as e:
            logger.error(RESET_PASSWORD_ERROR.format(str(e)))
    
    def _validate_authentication(self, context: params.KeeperParams) -> bool:
        """Validate that user is authenticated."""
        if not context.auth:
            logger.warning(RESET_PASSWORD_NOT_LOGGED_IN)
            return False
        return True
    
    def _handle_sso_deletion(self, kwargs: dict) -> bool:
        """Handle SSO password deletion request."""
        if kwargs.get('delete_sso'):
            logger.warning(RESET_PASSWORD_SSO_NOT_IMPLEMENTED)
            return True
        return False
    
    def _change_password_non_interactive(self, context: params.KeeperParams, current_password: str, new_password: str):
        """Change password using provided arguments."""
        auth = context.auth
        logger.info(RESET_PASSWORD_CHANGING.format(auth.auth_context.username))
        
        if not self._validate_current_password(auth, current_password):
            return
            
        self._perform_breachwatch_scan(context.vault, new_password)
        login.LoginAPI.change_master_password_command(auth, new_password)
        logger.info(RESET_PASSWORD_SUCCESS)
        self._update_context_password(context, new_password)
    
    def _change_password_interactive(self, context: params.KeeperParams):
        """Change password using interactive prompts."""
        new_password = login.LoginAPI.change_master_password(context.auth)
        if new_password:
            logger.info(RESET_PASSWORD_SUCCESS)
            self._update_context_password(context, new_password)
        else:
            logger.warning(RESET_PASSWORD_CANCELLED)
    
    def _update_context_password(self, context: params.KeeperParams, new_password: str):
        """Update context with new password."""
        context.password = new_password
    
    def _validate_current_password(self, auth: keeper_auth.KeeperAuth, current_password: str) -> bool:
        """Validate the current password before allowing change."""
        try:
            current_salt = auth.execute_auth_rest(
                'authentication/get_salt_and_iterations',
                None,
                response_type=APIRequest_pb2.Salt
            )
            
            if current_salt:
                auth_hash = crypto.derive_keyhash_v1(current_password, current_salt.salt, current_salt.iterations)
                
                rq = APIRequest_pb2.MasterPasswordReentryRequest()
                rq.pbkdf2Password = utils.base64_url_encode(auth_hash)
                rq.action = APIRequest_pb2.UNMASK
                
                rs = auth.execute_auth_rest(
                    'authentication/validate_master_password',
                    rq,
                    response_type=APIRequest_pb2.MasterPasswordReentryResponse,
                    payload_version=1
                )
                
                if rs.status != APIRequest_pb2.MP_SUCCESS:
                    logger.warning(RESET_PASSWORD_CURRENT_INCORRECT)
                    return False
                    
                return True
            else:
                return True
                
        except Exception:
            logger.warning(RESET_PASSWORD_CURRENT_INCORRECT)
            return False
    
    def _perform_breachwatch_scan(self, vault: vault_online.VaultOnline, password: str):
        """Perform BreachWatch scan on the new password."""
        try:
            if vault and vault.breach_watch_plugin():
                logger.info(RESET_PASSWORD_BREACHWATCH_SCAN)
                
                breach_watch = vault.breach_watch_plugin().breach_watch
                scan_results = breach_watch.scan_passwords([password])
                
                if scan_results:
                    for result in scan_results:
                        status = 'WEAK' if result[1].breachDetected else 'GOOD'
                        logger.info(RESET_PASSWORD_BREACHWATCH_RESULT.format(status))
                        
                        if result[1].euid:
                            breach_watch.delete_euids([result[1].euid])
        except Exception:
            pass
