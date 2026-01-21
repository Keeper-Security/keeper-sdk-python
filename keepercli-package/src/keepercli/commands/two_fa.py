import argparse
import datetime
import json

from . import base
from ..params import KeeperParams
from ..helpers import report_utils
from .. import api, prompt_utils

from keepersdk import utils
from keepersdk.proto import APIRequest_pb2
from keepersdk.authentication import two_fa_utils
from keepersdk.errors import KeeperApiError

logger = api.get_logger()

# Constants
NEVER_EXPIRE_TIMESTAMP = 3_000_000_000_000
MILLISECONDS_TO_SECONDS = 1000

METHOD_CHOICES = ['totp', 'key', 'sms', 'duo', 'backup']

# TFA Restriction keys
ALL_TFA_RESTRICTIONS = {
    'require_security_key_pin',
    'restrict_two_factor_channel_text',
    'restrict_two_factor_channel_google',
    'restrict_two_factor_channel_duo',
    'restrict_two_factor_channel_security_key',
    'restrict_two_factor_channel_rsa',
    'restrict_two_factor_channel_dna'
}

# Duo capabilities
DUO_CAPABILITIES = ('mobile_otp', 'sms', 'voice')
DUO_CAPABILITY_SMS = 'sms'
DUO_CAPABILITY_VOICE = 'voice'
DUO_CAPABILITY_MOBILE_OTP = 'mobile_otp'
DUO_CAPABILITY_DISPLAY_NAMES = {
    'sms': 'Send a Text Message',
    'voice': 'Make a Voice Call',
    'mobile_otp': 'OTP Code on Mobile'
}

# Method to Channel Type mapping
METHOD_TO_CHANNEL_TYPE = {
    'totp': APIRequest_pb2.TWO_FA_CT_TOTP,
    'sms': APIRequest_pb2.TWO_FA_CT_SMS,
    'key': APIRequest_pb2.TWO_FA_CT_WEBAUTHN,
    'duo': APIRequest_pb2.TWO_FA_CT_DUO,
    'backup': APIRequest_pb2.TWO_FA_CT_BACKUP
}

# Method to restriction key mapping
METHOD_TO_RESTRICTION = {
    'totp': 'restrict_two_factor_channel_google',
    'sms': 'restrict_two_factor_channel_text',
    'key': 'restrict_two_factor_channel_security_key'
}

# Channel Type to Value Type mapping for validation
CHANNEL_TYPE_TO_VALUE_TYPE = {
    APIRequest_pb2.TWO_FA_CT_TOTP: APIRequest_pb2.TWO_FA_CODE_TOTP,
    APIRequest_pb2.TWO_FA_CT_SMS: APIRequest_pb2.TWO_FA_CODE_SMS,
    APIRequest_pb2.TWO_FA_CT_WEBAUTHN: APIRequest_pb2.TWO_FA_RESP_WEBAUTHN,
    APIRequest_pb2.TWO_FA_CT_DUO: APIRequest_pb2.TWO_FA_CODE_DUO
}

# Error messages
ERROR_VAULT_NOT_INITIALIZED = "Vault is not initialized. Login to initialize the vault."
ERROR_METHOD_DISABLED_TOTP = 'Authenticator App (TOTP) 2FA method is disabled by the Administrator'
ERROR_METHOD_DISABLED_SMS = 'Text Message (SMS) 2FA method is disabled by the Administrator'
ERROR_METHOD_DISABLED_KEY = 'Security Key 2FA method is disabled by the Administrator'
ERROR_METHOD_NOT_SUPPORTED = '2FA method "{}" is not supported'
ERROR_NAME_REQUIRED = '"name" argument is required'
ERROR_CHANNEL_NOT_FOUND = '2FA channel "{}" not found'

# Messages
MSG_NO_2FA_METHODS = 'No 2FA methods are found'
MSG_2FA_EXPIRES = '2FA authentication expires: %s\n'
MSG_2FA_METHOD_ADDED = '2FA method is added'
MSG_2FA_CHANNEL_DELETED = '2FA channel is deleted'
MSG_ENTER_PHONE = '\nEnter your phone number for text messages: '
MSG_DUO_ENROLL_URL = "Enroll URL"
MSG_DUO_DEVICE_PHONE = 'Device Phone Number: {}'
MSG_DUO_SELECTION_PROMPT = 'We\'ll send you a text message or call with a passcode to your device:'
MSG_DUO_CANCEL = '  q. Cancel'
MSG_DUO_SELECTION = 'Selection: '
MSG_DUO_ACTION_NOT_SUPPORTED = 'Action "{}" is not supported.'
MSG_VERIFICATION_CODE = 'Verification Code: '
MSG_INVALID_2FA_CODE = 'Invalid 2FA code: (%s): %s '
MSG_QR_CODE_NOT_INSTALLED = 'QR Code library is not installed.\npip install pyqrcode'
MSG_DELETE_CHANNEL_PROMPT = 'Do you want to delete 2FA channel "{}"?'

REPORT_HEADERS = ['method', 'channel_uid', 'name', 
                  'created', 'phone_number']

BACKUP_CODES_TITLE = 'Backup Codes'
TOTP_URL_TEMPLATE = 'otpauth://totp/Keeper:{}?secret={}'
QR_CODE_COLORS = ('black', 'white')
CANCEL_CHOICES = ('q', 'Q')
YES_CHOICES = ('y', 'Y')
DEFAULT_CONFIRMATION = 'n'

class TwoFaCommand(base.GroupCommand):

    def __init__(self):
        super().__init__('Two-Factor Authentication')
        self.register_command(ListTwoFaCommand(), 'list')
        self.register_command(AddTwoFaCommand(), 'add')
        self.register_command(DeleteTwoFaCommand(), 'delete')
        self.default_verb = 'list'

    @staticmethod
    def two_factor_channel_to_desc(channel):
        """Convert channel type to human-readable description."""
        channel_descriptions = {
            APIRequest_pb2.TWO_FA_CT_TOTP: 'TOTP',
            APIRequest_pb2.TWO_FA_CT_SMS: 'SMS',
            APIRequest_pb2.TWO_FA_CT_DUO: 'DUO',
            APIRequest_pb2.TWO_FA_CT_RSA: 'RSA SecurID',
            APIRequest_pb2.TWO_FA_CT_U2F: 'U2F',
            APIRequest_pb2.TWO_FA_CT_WEBAUTHN: 'Security Key',
            APIRequest_pb2.TWO_FA_CT_DNA: 'Keeper DNA (Watch)',
            APIRequest_pb2.TWO_FA_CT_BACKUP: 'Backup Codes'
        }
        return channel_descriptions.get(channel, 'Unknown')

class ListTwoFaCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='2fa list',
            description='List all two-factor authentication methods',
            parents=[base.report_output_parser]
        )
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise ValueError(ERROR_VAULT_NOT_INITIALIZED)
        
        vault = context.vault
        response = two_fa_utils.get_two_fa_list(vault)
        
        if not response or response.expireOn <= 0:
            logger.info(MSG_NO_2FA_METHODS)
            return
        
        expire_at = self._format_expiry_time(response.expireOn)
        if expire_at:
            logger.info(MSG_2FA_EXPIRES, expire_at)
        
        table = self._build_channel_table(response.channels)
        fmt = kwargs.get('format')
        header = self._get_report_headers(fmt)
        
        return report_utils.dump_report_data(
            table, header, fmt=fmt, filename=kwargs.get('output'), row_number=True
        )
    
    @staticmethod
    def _format_expiry_time(expire_on):
        """Format expiry timestamp to human-readable string."""
        if expire_on > NEVER_EXPIRE_TIMESTAMP:
            return 'Never'
        dt = datetime.datetime.fromtimestamp(expire_on // MILLISECONDS_TO_SECONDS)
        return dt.isoformat()
    
    @staticmethod
    def _build_channel_table(channels):
        """Build table rows from channel data."""
        table = []
        for channel in channels:
            created_on = datetime.datetime.fromtimestamp(
                channel.createdOn // MILLISECONDS_TO_SECONDS
            )
            row = [
                TwoFaCommand.two_factor_channel_to_desc(channel.channelType),
                utils.base64_url_encode(channel.channel_uid),
                channel.channelName,
                created_on,
                channel.phoneNumber
            ]
            table.append(row)
        return table
    
    @staticmethod
    def _get_report_headers(format_type):
        """Get report headers, formatted if not JSON."""
        if format_type == 'json':
            return REPORT_HEADERS
        return [report_utils.field_to_title(x) for x in REPORT_HEADERS]

class AddTwoFaCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='2fa add', description='Add 2FA method')
        AddTwoFaCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '--method', '-m',
            dest='method',
            action='store',
            required=True,
            choices=METHOD_CHOICES,
            help='2FA auth method'
        )
        parser.add_argument('--name', dest='name', action='store', help='2FA auth name')
        parser.add_argument(
            '--key-pin',
            dest='key_pin',
            action='store_true',
            help='force using Security Key PIN'
        )

    def execute(self, context: KeeperParams, **kwargs):
        """Execute the add 2FA method command."""
        if not context.vault:
            raise ValueError(ERROR_VAULT_NOT_INITIALIZED)
        
        vault = context.vault
        method = kwargs.get('method')
        tfa_restrictions = self._get_tfa_restrictions(vault)
        
        channel_type = self._get_channel_type(method, tfa_restrictions)
        channel_uid = utils.base64_url_decode(utils.generate_uid())
        channel_name = kwargs.get('name') or ''
        
        phone_number, duo_push_type = self._handle_channel_setup(
            vault, channel_type, context
        )
        if self._is_setup_cancelled(channel_type, phone_number, duo_push_type):
            return
        
        response = two_fa_utils.add_two_fa_method(
            vault=vault,
            channel_type=channel_type,
            channel_uid=channel_uid,
            channel_name=channel_name,
            phone_number=phone_number or '',
            duo_push_type=duo_push_type or APIRequest_pb2.TWO_FA_PUSH_NONE
        )
        
        if self._handle_channel_specific_setup(
            vault, channel_type, response, channel_uid, context, kwargs
        ):
            return
        
        value_type = self._get_value_type_for_channel(channel_type)
        self._validate_2fa_code(vault, channel_uid, value_type)
    
    @staticmethod
    def _get_tfa_restrictions(vault):
        """Get TFA restrictions from vault enforcements."""
        tfa_restrictions = set()
        enforcements = vault.keeper_auth.auth_context.enforcements
        if not enforcements or 'booleans' not in enforcements:
            return tfa_restrictions
        
        booleans = enforcements['booleans']
        for item in booleans:
            key = (item.get('key') or '').lower()
            if key in ALL_TFA_RESTRICTIONS:
                tfa_restrictions.add(key)
        
        return tfa_restrictions
    
    @staticmethod
    def _get_channel_type(method, tfa_restrictions):
        """Get channel type for method and validate restrictions."""
        if method not in METHOD_TO_CHANNEL_TYPE:
            raise base.CommandError(ERROR_METHOD_NOT_SUPPORTED.format(method))
        
        restriction_key = METHOD_TO_RESTRICTION.get(method)
        if restriction_key and restriction_key in tfa_restrictions:
            error_messages = {
                'totp': ERROR_METHOD_DISABLED_TOTP,
                'sms': ERROR_METHOD_DISABLED_SMS,
                'key': ERROR_METHOD_DISABLED_KEY
            }
            raise base.CommandError(error_messages.get(method, ''))
        
        return METHOD_TO_CHANNEL_TYPE[method]
    
    def _handle_channel_setup(self, vault, channel_type, context):
        """Handle channel-specific setup (SMS phone, Duo selection)."""
        phone_number = None
        duo_push_type = None
        
        if channel_type == APIRequest_pb2.TWO_FA_CT_SMS:
            phone_number = self._handle_sms_setup()
        elif channel_type == APIRequest_pb2.TWO_FA_CT_DUO:
            duo_push_type = self._handle_duo_setup(vault)
        
        return phone_number, duo_push_type
    
    @staticmethod
    def _is_setup_cancelled(channel_type, phone_number, duo_push_type):
        """Check if setup was cancelled by user."""
        if channel_type == APIRequest_pb2.TWO_FA_CT_SMS:
            return phone_number is None
        if channel_type == APIRequest_pb2.TWO_FA_CT_DUO:
            return duo_push_type is None
        return False
    
    @staticmethod
    def _handle_sms_setup():
        """Handle SMS phone number input."""
        try:
            phone_number = input(MSG_ENTER_PHONE)
            return phone_number if phone_number else None
        except KeyboardInterrupt:
            return None
    
    def _handle_duo_setup(self, vault):
        """Handle Duo setup and return push type."""
        duo_response = vault.keeper_auth.execute_auth_rest(
            rest_endpoint='authentication/2fa_duo_status',
            request=None,
            response_type=APIRequest_pb2.TwoFactorDuoStatus
        )
        
        if duo_response.enroll_url:
            logger.warning(duo_response.message)
            logger.warning(MSG_DUO_ENROLL_URL)
            logger.info(duo_response.enroll_url)
            return None
        
        capabilities = [
            cap for cap in duo_response.capabilities
            if cap in DUO_CAPABILITIES
        ]
        
        if not capabilities:
            return None
        
        logger.info(MSG_DUO_DEVICE_PHONE.format(duo_response.phoneNumber))
        logger.info(MSG_DUO_SELECTION_PROMPT)
        
        for idx, capability in enumerate(capabilities, 1):
            display_name = DUO_CAPABILITY_DISPLAY_NAMES.get(
                capability, capability
            )
            logger.info(f'  {idx}. {display_name}')
        
        logger.info(MSG_DUO_CANCEL)
        
        return self._get_duo_push_type_selection(capabilities)
    
    @staticmethod
    def _get_duo_push_type_selection(capabilities):
        """Get Duo push type from user selection."""
        while True:
            try:
                answer = input(MSG_DUO_SELECTION)
                if answer in CANCEL_CHOICES:
                    return None
                
                if answer and answer.isnumeric():
                    code = int(answer)
                    if 0 < code <= len(capabilities):
                        selected_capability = capabilities[code - 1]
                        return {
                            DUO_CAPABILITY_SMS: APIRequest_pb2.TWO_FA_PUSH_DUO_TEXT,
                            DUO_CAPABILITY_VOICE: APIRequest_pb2.TWO_FA_PUSH_DUO_CALL,
                            DUO_CAPABILITY_MOBILE_OTP: APIRequest_pb2.TWO_FA_PUSH_NONE
                        }.get(selected_capability, APIRequest_pb2.TWO_FA_PUSH_NONE)
                
                logger.info(MSG_DUO_ACTION_NOT_SUPPORTED.format(answer))
            except (KeyboardInterrupt, ValueError):
                return None
    
    def _handle_channel_specific_setup(self, vault, channel_type, response, 
                                       channel_uid, context, kwargs):
        """Handle channel-specific post-setup (backup codes, webauthn, totp)."""
        if channel_type == APIRequest_pb2.TWO_FA_CT_BACKUP:
            self._handle_backup_codes(response)
            return True
        
        if channel_type == APIRequest_pb2.TWO_FA_CT_WEBAUTHN:
            self._handle_webauthn_setup(vault, response, channel_uid, kwargs)
            return True
        
        if channel_type == APIRequest_pb2.TWO_FA_CT_TOTP:
            self._handle_totp_setup(response, context)
        
        return False
    
    @staticmethod
    def _handle_backup_codes(response):
        """Display backup codes."""
        codes = list(response.backupKeys)
        table = []
        for idx in range(0, len(codes), 2):
            table.append(codes[idx:idx + 2])
        report_utils.dump_report_data(
            table, ('', ''), title=BACKUP_CODES_TITLE, no_header=True
        )
    
    @staticmethod
    def _handle_webauthn_setup(vault, response, channel_uid, kwargs):
        """Handle WebAuthn security key setup."""
        try:
            from ..login import FidoCliInteraction
            from keepersdk.authentication.yubikey import yubikey_register
            
            request = json.loads(response.challenge)
            force_pin = kwargs.get('key_pin') is True
            fido_response = yubikey_register(
                request, force_pin, user_interaction=FidoCliInteraction()
            )
            
            if not fido_response:
                return
            
            attestation = {
                'id': fido_response.id,
                'rawId': utils.base64_url_encode(fido_response.raw_id),
                'response': {
                    'attestationObject': utils.base64_url_encode(
                        fido_response.response.attestation_object
                    ),
                    'clientDataJSON': fido_response.response.client_data.b64
                },
                'type': 'public-key',
                'clientExtensionResults': (
                    dict(fido_response.client_extension_results)
                    if fido_response.client_extension_results else {}
                )
            }
            
            two_fa_utils.validate_two_fa_method(
                vault=vault,
                channel_uid=channel_uid,
                value_type=APIRequest_pb2.TWO_FA_RESP_WEBAUTHN,
                value=json.dumps(attestation),
                expire_in=APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY
            )
            logger.info(MSG_2FA_METHOD_ADDED)
        except ImportError as e:
            logger.warning(e)
            display_fido2_warning()
        except Exception as e:
            logger.warning(e)
    
    @staticmethod
    def _handle_totp_setup(response, context):
        """Handle TOTP setup and display QR code."""
        url = TOTP_URL_TEMPLATE.format(
            context.auth.auth_context.username,
            response.challenge
        )
        logger.info(f'TOTP URL:\n{url}')
        
        try:
            import pyqrcode
            qr_code = pyqrcode.create(url)
            logger.info(qr_code.terminal(*QR_CODE_COLORS))
        except ModuleNotFoundError:
            logger.error(MSG_QR_CODE_NOT_INSTALLED)
    
    @staticmethod
    def _get_value_type_for_channel(channel_type):
        """Get value type for channel type validation."""
        return CHANNEL_TYPE_TO_VALUE_TYPE.get(
            channel_type,
            APIRequest_pb2.TWO_FA_CODE_TOTP
        )
    
    @staticmethod
    def _validate_2fa_code(vault, channel_uid, value_type):
        """Validate 2FA code with user input."""
        while True:
            try:
                answer = input(MSG_VERIFICATION_CODE)
                if not answer:
                    continue
                
                try:
                    two_fa_utils.validate_two_fa_method(
                        vault=vault,
                        channel_uid=channel_uid,
                        value_type=value_type,
                        value=answer,
                        expire_in=APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY
                    )
                    logger.info(MSG_2FA_METHOD_ADDED)
                    return
                except KeeperApiError as kae:
                    logger.warning(
                        MSG_INVALID_2FA_CODE,
                        kae.result_code,
                        kae.message
                    )
            except KeyboardInterrupt:
                return


warned_on_fido_package = False
install_fido_package_warning = """
    You can use Security Key with KeeperSDK:
    Upgrade your Python interpreter to 3.10 or newer
    and make sure fido2 package is 2.0.0 or newer
"""


def display_fido2_warning():
    global warned_on_fido_package

    if not warned_on_fido_package:
        logger.warning(install_fido_package_warning)
    warned_on_fido_package = True


class DeleteTwoFaCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='2fa delete',
            description='Delete a two-factor authentication method'
        )
        DeleteTwoFaCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '--force',
            dest='force',
            action='store_true',
            help='do not prompt for confirmation'
        )
        parser.add_argument('name', help='2FA method UID or name')

    def execute(self, context: KeeperParams, **kwargs):
        if not context.vault:
            raise ValueError(ERROR_VAULT_NOT_INITIALIZED)
        
        vault = context.vault
        name = kwargs.get('name')
        
        if not name:
            raise base.CommandError(ERROR_NAME_REQUIRED)
        
        response = two_fa_utils.get_two_fa_list(vault)
        if not response:
            logger.info(MSG_NO_2FA_METHODS)
            return
        
        channel = self._find_channel_by_name(response.channels, name)
        if not channel:
            raise base.CommandError(ERROR_CHANNEL_NOT_FOUND.format(name))
        
        if not self._confirm_deletion(channel, kwargs.get('force')):
            return
        
        two_fa_utils.delete_two_fa_method(vault, channel.channel_uid)
        logger.info(MSG_2FA_CHANNEL_DELETED)
    
    @staticmethod
    def _find_channel_by_name(channels, name):
        """Find channel by UID or name (case-insensitive)."""
        channel = next(
            (ch for ch in channels if utils.base64_url_encode(ch.channel_uid) == name),
            None
        )
        
        if channel:
            return channel
        
        name_lower = name.casefold()
        return next(
            (ch for ch in channels if ch.channelName.casefold() == name_lower),
            None
        )
    
    @staticmethod
    def _confirm_deletion(channel, force):
        """Confirm deletion with user if not forced."""
        if force:
            return True
        
        channel_name = channel.channelName or utils.base64_url_encode(channel.channel_uid)
        answer = prompt_utils.user_choice(
            MSG_DELETE_CHANNEL_PROMPT.format(channel_name),
            'yn',
            DEFAULT_CONFIRMATION
        )
        return answer in YES_CHOICES
