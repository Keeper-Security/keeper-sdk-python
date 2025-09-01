import datetime
import json
import os
import re
import urllib.parse
import webbrowser
from typing import Dict, List, Union, Optional, Any, Tuple

import fido2.client
import pyperclip
from prompt_toolkit.formatted_text import FormattedText

from keepersdk import errors, utils, crypto
from keepersdk.authentication import login_auth, keeper_auth, endpoint
from keepersdk.proto import APIRequest_pb2, enterprise_pb2, ssocloud_pb2
from keepersdk.authentication.yubikey import yubikey_authenticate, IKeeperUserInteraction

from . import prompt_utils, constants
from .params import KeeperParams


class FidoCliInteraction(fido2.client.UserInteraction, IKeeperUserInteraction):
    def output_text(self, text: str) -> None:
        prompt_utils.output_text(text)

    def prompt_up(self):
        prompt_utils.output_text("\nTouch the flashing Security key to authenticate or "
              "press Ctrl-C to resume with the primary two factor authentication...")

    def request_pin(self, permissions, rd_id):
        prompt = "Enter Security Key PIN: "
        return prompt_utils.input_password(prompt)

    def request_uv(self, permissions, rd_id):
        prompt_utils.output_text("User Verification required.")
        return True


class LoginFlow:
    @staticmethod
    def login(context: KeeperParams, *,
              username: Optional[str] = None,
              password: Optional[str] = None,
              sso_master_password: bool = False,
              resume_session: bool = False) -> Optional[bool]:

        if not username:
            conf = context.get()
            username = conf.last_login
            resume_session = True
        if not username:
            raise Exception('Keeper username is not provided')

        logger = utils.get_logger()
        logger.info('Logging in to Keeper as "%s"', username)

        keeper_endpoint = endpoint.KeeperEndpoint(context, context.server)
        auth = login_auth.LoginAuth(keeper_endpoint)
        try:
            def on_next_step():
                prompt_utils.cancel_input()

            auth.on_next_step = on_next_step

            def keeper_redirect(region):
                prompt_utils.output_text(
                    FormattedText([('', 'Redirected to region: '), ('class:h3', region)]))

            auth.on_region_changed = keeper_redirect

            passwords = []
            if password:
                passwords.append(password)
            if context.password:
                passwords.append(context.password)

            auth.resume_session = resume_session
            auth.alternate_password = sso_master_password

            auth.login(username, *passwords)

            from .biometric import check_biometric_previously_used
            biometric_present = check_biometric_previously_used(username)

            while not auth.login_step.is_final():
                step = auth.login_step

                if biometric_present and not isinstance(step, login_auth._ConnectedLoginStep):
                    biometric_present = LoginFlow.handle_biometric_password_step(auth, username, keeper_endpoint.client_version)
                elif isinstance(step, login_auth.LoginStepDeviceApproval):
                    LoginFlow.verify_device(step)
                elif isinstance(step, login_auth.LoginStepTwoFactor):
                    LoginFlow.handle_two_factor(context, step)
                elif isinstance(step, login_auth.LoginStepPassword):
                    LoginFlow.handle_verify_password(step)
                elif isinstance(step, login_auth.LoginStepSsoToken):
                    LoginFlow.handle_sso_redirect(step)
                elif isinstance(step, login_auth.LoginStepSsoDataKey):
                    LoginFlow.handle_sso_data_key(step)

            step = auth.login_step
            if isinstance(step, login_auth.LoginStepError):
                raise errors.KeeperApiError(step.code, step.message)
            if isinstance(step, login_auth.LoginStepConnected):
                authentication = step.take_keeper_auth()
                LoginFlow.post_login(context, authentication)
                return True
            else:
                raise errors.KeeperApiError('not_supported', f'Login step {type(step).__name__} is not supported')
        except KeyboardInterrupt:
            pass
        finally:
            auth.close()

    @staticmethod
    def handle_sso_data_key(step: login_auth.LoginStepSsoDataKey):
        menu = [
            ('1', 'Keeper Push. Send a push notification to your device.'),
            ('2', 'Admin Approval. Request your admin to approve this device.'),
            ('r', 'Resume SSO authentication after device is approved.'),
            ('q', 'Quit SSO authentication attempt and return to Commander prompt.'),
        ]
        lines: List[Any] = ['Approve this device by selecting a method below:']
        lines.extend((FormattedText([('class:h3', f'{command:>3}'), ('', f'. {text}')]) for command, text in menu))
        prompt_utils.output_text(*lines)

        while True:
            answer = prompt_utils.input_text('Selection: ')
            if answer is None:
                return
            if answer == 'q':
                raise KeyboardInterrupt()
            if answer == 'r':
                step.resume()
                break
            elif answer in ('1', '2'):
                step.request_data_key(login_auth.DataKeyShareChannel.KeeperPush if answer == '1' else
                                      login_auth.DataKeyShareChannel.AdminApproval)
            else:
                prompt_utils.output_text(f'Action \"{answer}\" is not supported.')

    @staticmethod
    def handle_sso_redirect(step: login_auth.LoginStepSsoToken):
        menu = [
            ('a', 'SSO User with a Master Password.'),
            ('c', 'Copy SSO Login URL to clipboard.'),
        ]
        try:
            wb = webbrowser.get()
            menu.append(('o', 'Navigate to SSO Login URL with the default web browser.'))
        except Exception:
            wb = None
        menu.extend((
            ('p', 'Paste SSO Token from clipboard.'),
            ('q', 'Quit SSO authentication attempt and return to Commander prompt.'),
        ))

        lines: List[Union[str, FormattedText]] = ['',
            'SSO Login URL:',
            FormattedText([('class:b', step.sso_login_url)]),
            'Navigate to SSO Login URL with your browser and complete authentication.',
            'Copy a returned SSO Token into clipboard.',
            'Paste that token into Commander',
            'NOTE: To copy SSO Token please click "Copy authentication token" button on "SSO Connect" page.',
            '',
        ]
        lines.extend((FormattedText([('class:h3', f'{action:>3}'), ('', f'. {text}')]) for action, text in menu))
        prompt_utils.output_text(*lines)

        while True:
            token: Optional[str]
            token = prompt_utils.input_text('Selection: ')
            if token == 'q':
                raise KeyboardInterrupt()
            if token == 'a':
                step.login_with_password()
                return
            if token == 'c':
                token = None
                try:
                    pyperclip.copy(step.sso_login_url)
                    prompt_utils.output_text('SSO Login URL is copied to clipboard.')
                except Exception:
                    prompt_utils.output_text('Failed to copy SSO Login URL to clipboard.')
            elif token == 'o':
                token = None
                if wb:
                    try:
                        wb.open_new_tab(step.sso_login_url)
                    except Exception:
                        prompt_utils.output_text('Failed to open web browser.')
            elif token == 'p':
                try:
                    token = pyperclip.paste()
                except Exception:
                    token = ''
                    prompt_utils.output_text('Failed to paste from clipboard')
            else:
                if len(token) < 10:
                    prompt_utils.output_text(f'Unsupported menu option: {token}')
                    continue

            if token:
                try:
                    step.set_sso_token(token)
                    break
                except errors.KeeperApiError as kae:
                    prompt_utils.output_text(f'SSO Login error: ({kae.result_code}) {kae.message}')

    @staticmethod
    def handle_verify_password(step: login_auth.LoginStepPassword):
        prompt_utils.output_text(f'\nEnter password for {step.username}')
        while True:
            password = prompt_utils.input_password('Password: ')
            if not password:
                raise KeyboardInterrupt()
            try:
                step.verify_password(password)
                break
            except errors.KeeperApiError as kae:
                prompt_utils.output_text('Invalid email or password combination, please re-enter.'
                                         if kae.result_code == 'auth_failed' else kae.message)

    @staticmethod
    def two_factor_channel_to_desc(channel_type: login_auth.TwoFactorChannel):
        if channel_type == login_auth.TwoFactorChannel.Authenticator:
            return 'TOTP (Google and Microsoft Authenticator)'
        if channel_type == login_auth.TwoFactorChannel.TextMessage:
            return 'Send SMS Code'
        if channel_type == login_auth.TwoFactorChannel.DuoSecurity:
            return 'DUO'
        if channel_type == login_auth.TwoFactorChannel.RSASecurID:
            return 'RSA SecurID'
        if channel_type == login_auth.TwoFactorChannel.SecurityKey:
            return 'WebAuthN (FIDO2 Security Key)'
        if channel_type == login_auth.TwoFactorChannel.KeeperDNA:
            return 'Keeper DNA (Watch)'
        if channel_type == login_auth.TwoFactorChannel.Backup:
            return 'Backup Code'
        return 'Not Supported'

    DurationCodes: Dict[login_auth.TwoFactorDuration, str] = {
        login_auth.TwoFactorDuration.EveryLogin: 'login',
        login_auth.TwoFactorDuration.Every12Hours: '12_hours',
        login_auth.TwoFactorDuration.EveryDay: '24_hours',
        login_auth.TwoFactorDuration.Every30Days: '30_days',
        login_auth.TwoFactorDuration.Forever: 'forever',
    }

    @staticmethod
    def two_factor_duration_to_code(duration: login_auth.TwoFactorDuration) -> str:
        return LoginFlow.DurationCodes.get(duration) or 'login'

    @staticmethod
    def two_factor_duration_to_description(duration: login_auth.TwoFactorDuration) -> str:
        return ('Require Every Login' if duration == login_auth.TwoFactorDuration.EveryLogin else
                'Save on this Device Forever' if duration == login_auth.TwoFactorDuration.Forever else
                'Ask Every 12 hours' if duration == login_auth.TwoFactorDuration.Every12Hours else
                'Ask Every 24 hours' if duration == login_auth.TwoFactorDuration.EveryDay else
                'Ask Every 30 days')

    @staticmethod
    def two_factor_code_to_duration(text: str) -> login_auth.TwoFactorDuration:
        return next((dura for dura, code in LoginFlow.DurationCodes.items() if code == text),
                    login_auth.TwoFactorDuration.EveryLogin)

    warned_on_fido_package = False
    install_fido_package_warning = [
        'You can use Security Key with Commander:',
        FormattedText([('', 'Install fido2 package '), ('class:h3', "'pip install fido2'")])]

    @staticmethod
    def handle_two_factor(context: KeeperParams, step: login_auth.LoginStepTwoFactor):
        channels = [x for x in step.get_channels() if x.channel_type != login_auth.TwoFactorChannel.Other]
        menu = []
        for i in range(len(channels)):
            channel = channels[i]
            description = LoginFlow.two_factor_channel_to_desc(channel.channel_type)
            menu.append((str(i+1), f'{description} {channel.channel_name} {channel.phone}'))
        menu.append(('q', 'Quit authentication attempt and return to Commander prompt.'))

        lines: List[Any] = ['', 'This account requires 2FA Authentication']
        lines.extend((FormattedText([('', '  '), ('class:h3', action), ('', '. ' + text)]) for action, text in menu))
        prompt_utils.output_text(*lines)

        done = False
        selection: str
        while not done:
            selection = prompt_utils.input_text('Selection: ')
            if selection is None:
                return
            if selection in ('q', 'Q'):
                raise KeyboardInterrupt()
            try:
                assert selection.isnumeric()
                idx = 1 if not selection else int(selection)
                assert 1 <= idx <= len(channels)
                channel = channels[idx-1]
                description = LoginFlow.two_factor_channel_to_desc(channel.channel_type)
                prompt_utils.output_text(FormattedText([
                    ('', 'Selected '),
                    ('class:b', f'{idx}'),
                    ('', f'. {description}')]))
            except AssertionError:
                prompt_utils.output_text('Invalid entry, additional factors of authentication shown may be configured '
                                         'if not currently enabled.')
                continue

            # send push
            if channel.channel_type in (login_auth.TwoFactorChannel.TextMessage, login_auth.TwoFactorChannel.KeeperDNA,
                                        login_auth.TwoFactorChannel.DuoSecurity):
                action = next((x for x in step.get_channel_push_actions(channel.channel_uid)
                               if x in (login_auth.TwoFactorPushAction.TextMessage,
                                        login_auth.TwoFactorPushAction.KeeperDna)), None)
                if action:
                    step.send_push(channel.channel_uid, action)

            if channel.channel_type == login_auth.TwoFactorChannel.SecurityKey:
                try:
                    challenge = json.loads(channel.challenge)
                    signature = yubikey_authenticate(challenge, FidoCliInteraction())
                    if signature:
                        prompt_utils.output_text('Verified Security Key.')
                        step.send_code(channel.channel_uid, signature)
                        break
                except Exception as e:
                    utils.get_logger().error(e)

            else:   # 2FA code
                config_expiration = context.mfa_duration
                step.duration = LoginFlow.two_factor_code_to_duration(config_expiration)
                step.duration = min(step.duration, channel.max_expiration)
                available_dura = sorted((x for x in LoginFlow.DurationCodes.keys() if x <= channel.max_expiration))
                available_codes = [LoginFlow.two_factor_duration_to_code(x) for x in available_dura]
                suggests = []
                suggests.extend(available_codes)
                suggests.extend((f'2fa_duration={x}' for x in available_codes))
                while True:
                    mfa_description = LoginFlow.two_factor_duration_to_description(step.duration)
                    prompt_exp = f'\n2FA Code Duration: {mfa_description}.' \
                                 f'\nTo change duration: 2fa_duration={("|".join(available_codes))}'
                    prompt_utils.output_text(prompt_exp)

                    selection = prompt_utils.input_text(
                        '\nEnter 2FA Code or Duration: ', auto_suggest=prompt_utils.CommandSuggest(suggests))
                    if not selection:
                        return
                    if selection in available_codes:
                        step.duration = LoginFlow.two_factor_code_to_duration(selection)
                    elif selection.startswith('2fa_duration='):
                        code = selection[len('2fa_duration='):]
                        if code in available_codes:
                            step.duration = LoginFlow.two_factor_code_to_duration(code)
                        else:
                            prompt_utils.output_text(f'Invalid 2FA duration: {code}')
                    else:
                        try:
                            step.send_code(channel.channel_uid, selection)
                            prompt_utils.output_text(FormattedText([('class:h3', 'Successfully verified 2FA Code.')]))
                            return
                        except errors.KeeperApiError as kae:
                            prompt_utils.output_text(f'Invalid 2FA code: ({kae.result_code}) {kae.message}')

    @staticmethod
    def handle_biometric_password_step(login_auth_context: login_auth.LoginAuth, username: str, client_version: str) -> bool:
        """Handle biometric authentication as part of the password verification step"""
        logger = utils.get_logger()
        
        while True:
            try:
                from .biometric.commands.verify import BiometricVerifyCommand
                
                logger.info("Attempting biometric authentication...")
                logger.info("Press Ctrl+C to skip biometric and use password")
                
                
                auth_helper = BiometricVerifyCommand()
                biometric_result = auth_helper.biometric_authenticate(login_auth_context, client_version, username, purpose='login')

                if biometric_result and biometric_result.isValid:
                    logger.info("Biometric authentication successful!")
                    login_auth._resume_login(login_auth_context, biometric_result.encryptedLoginToken, method=APIRequest_pb2.EXISTING_ACCOUNT, login_type=APIRequest_pb2.PASSKEY_BIO)
                    return True
                else:
                    logger.info("Biometric authentication failed")
                    prompt_utils.output_text("Biometric authentication failed. Please use password authentication.")
                    break
                    
            except KeyboardInterrupt:
                logger.info("Biometric authentication cancelled by user")
                prompt_utils.output_text("Biometric authentication cancelled. Using password authentication.")
                break
                    
            except Exception as e:
                error_message = str(e).lower()
                
                if "device_needs_approval" in error_message or "device approval" in error_message:
                    logger.error(f"\nBiometric Login Failed")
                    logger.warning(f"Device registration required for biometric authentication.")
                    logger.warning(f"\nPlease run: this-device register")
                    logger.warning("Then try biometric login again.")
                    prompt_utils.output_text("Device needs approval for biometric authentication. Using password authentication.")
                    break
                else:
                    logger.info(f"Biometric authentication error: {e}")
                    prompt_utils.output_text("Biometric authentication error. Using password authentication.")
                    break

        return False

    @staticmethod
    def verify_device(step: login_auth.LoginStepDeviceApproval):
        menu = [
            ('email_send', 'to send email'),
            ('email_code=<code>', 'to validate verification code sent via email'),
            ('keeper_push', 'to send Keeper Push notification'),
            ('2fa_send', 'to send 2FA code'),
            ('2fa_code=<code>', 'to validate a code provided by 2FA application'),
            ('<Enter>', 'to resume'),
        ]
        lines: List[Any] = ['Approve by selecting a method below']
        lines.extend((FormattedText([('', '  '), ('class:h3', action), ('', ' ' + text)]) for action, text in menu))
        prompt_utils.output_text(*lines)

        suggests = []
        for x in menu:
            code, sep, rest = x[0].partition('=')
            suggests.append(code + sep if sep else code)

        selection: str = prompt_utils.input_text('Type your selection or <Enter> to resume: ',
                                                 auto_suggest=prompt_utils.CommandSuggest(suggests))
        if selection is None:
            return
        if selection in ('email_send', 'es'):
            step.send_push(channel=login_auth.DeviceApprovalChannel.Email)
            prompt_utils.output_text([
                'An email with instructions has been sent.'
                'Press <Enter> when approved.'])
        elif selection.startswith('email_code='):
            code = selection[len('email_code='):]
            step.send_code(channel=login_auth.DeviceApprovalChannel.Email, code=code)
            prompt_utils.output_text("\nSuccessfully verified email code.")
        elif selection in ('keeper_push', 'kp'):
            step.send_push(channel=login_auth.DeviceApprovalChannel.KeeperPush)
            prompt_utils.output_text([
                'Successfully made a push notification to the approved device.',
                'Press <Enter> when approved.'])
        elif selection in ('2fa_send', '2fs'):
            step.send_push(channel=login_auth.DeviceApprovalChannel.TwoFactor)
            prompt_utils.output_text('2FA code was sent.')
        elif selection.startswith('2fa_code='):
            code = selection[len('2fa_code='):]
            step.send_code(channel=login_auth.DeviceApprovalChannel.TwoFactor, code=code)
            prompt_utils.output_text("Successfully verified 2FA code.")
        else:
            step.resume()

    @staticmethod
    def post_login(context: KeeperParams, auth: keeper_auth.KeeperAuth):
        if auth.auth_context.session_token_restriction != keeper_auth.SessionTokenRestriction.Unrestricted:
            if auth.auth_context.session_token_restriction == keeper_auth.SessionTokenRestriction.AccountExpired:
                msg = (
                    'Your Keeper account has expired. Please open the Keeper app to renew or visit the Web '
                    'Vault at https://keepersecurity.com/vault'
                )
                raise Exception(msg)
            if auth.auth_context.session_token_restriction == keeper_auth.SessionTokenRestriction.AccountRecovery:
                prompt_utils.output_text(
                    'Your Master Password has expired, you are required to change it before you can login.')
                password = LoginAPI.change_master_password(auth)
                if password:
                    context.password = password
                    LoginFlow.login(context)
                else:
                    raise Exception('Change master password failed')
            elif auth.auth_context.session_token_restriction == keeper_auth.SessionTokenRestriction.ShareAccount:
                prompt_utils.output_text('Account transfer required.')
                _ = LoginAPI.accept_account_transfer_consent(auth)
                

        if auth.auth_context.session_token_restriction != keeper_auth.SessionTokenRestriction.Unrestricted:
            raise Exception('Please log into the Web Vault to update your account settings.')

        context.auth = auth


class LoginAPI:
    @staticmethod
    def get_default_password_rules(
            username: str, keeper_endpoint: endpoint.KeeperEndpoint) -> Tuple[List[APIRequest_pb2.PasswordRules], int]:
        rq = enterprise_pb2.DomainPasswordRulesRequest()
        rq.username = username

        rs = keeper_endpoint.execute_rest(
            'authentication/get_domain_password_rules', rq, response_type=APIRequest_pb2.NewUserMinimumParams)
        assert rs is not None
        rules = []
        for regexp, description in zip(rs.passwordMatchRegex, rs.passwordMatchDescription):
            rule = APIRequest_pb2.PasswordRules()
            rule.match = True
            rule.pattern = regexp
            rule.description = description
            rules.append(rule)

        return rules, rs.minimumIterations

    @staticmethod
    def change_master_password(
            auth: keeper_auth.KeeperAuth, password_rules: Optional[List[APIRequest_pb2.PasswordRules]]=None,
            min_iterations: Optional[int]=None) -> Optional[str]:

        if password_rules is None:
            password_rules, min_iterations = \
                LoginAPI.get_default_password_rules(auth.auth_context.username, auth.keeper_endpoint)

        logger = utils.get_logger()

        try:
            while True:
                prompt_utils.output_text('Please choose a new Master Password.')
                password = prompt_utils.input_password('... {0:>24}: '.format('Master Password')).strip()
                if not password:
                    raise KeyboardInterrupt()
                password2 = prompt_utils.input_password('... {0:>24}: '.format('Re-Enter Password')).strip()

                if password == password2:
                    failed_rules = []
                    for rule in password_rules:
                        pattern = re.compile(rule.pattern)
                        if not re.match(pattern, password):
                            failed_rules.append(rule.description)
                    if len(failed_rules) == 0:
                        LoginAPI.change_master_password_command(
                            auth, password, min_iterations or constants.PBKDF2_ITERATIONS)
                        logger.debug('Password changed')
                        return password
                    else:
                        for description in failed_rules:
                            logger.warning(f'\t{description}')
                else:
                    logger.warning('Passwords do not match.')
        except KeyboardInterrupt:
            logger.info('Canceled')

    @staticmethod
    def change_master_password_command(auth: keeper_auth.KeeperAuth, password: str, iterations: int=0) -> None:
        iterations = max(iterations, constants.PBKDF2_ITERATIONS)
        auth_salt = os.urandom(16)
        auth_verifier = utils.create_auth_verifier(password, auth_salt, iterations)
        data_salt = os.urandom(16)
        encryption_params = utils.create_encryption_params(password, data_salt, iterations, auth.auth_context.data_key)
        rq = {
            'command': 'change_master_password',
            'auth_verifier': utils.base64_url_encode(auth_verifier),
            'encryption_params': utils.base64_url_encode(encryption_params),
        }
        auth.execute_auth_command(rq)

    @staticmethod
    def accept_account_transfer_consent(auth: keeper_auth.KeeperAuth) -> bool:
        share_to_roles = auth.auth_context.settings.get('share_account_to')
        share_by_time = auth.auth_context.settings.get('must_perform_account_share_by')
        if not isinstance(share_to_roles, list) or not isinstance(share_by_time, (int, float)):
            return False

        share_account_by = datetime.datetime.fromtimestamp(share_by_time / 1000)
        prompt_utils.output_text(constants.ACCOUNT_TRANSFER_MSG.format(share_account_by.strftime('%a, %b %d %Y')))

        expired = datetime.datetime.today() > share_account_by
        input_options = 'Accept/L(ogout)' if expired else 'Accept/L(ater)'
        answer = prompt_utils.input_text(f'Do you accept Account Transfer policy? {input_options}: ')
        answer = answer.lower()
        if answer.lower() == 'accept':
            for role in share_to_roles:
                request = {
                    'command': 'share_account',
                    'to_role_id': role['role_id'],
                }
                if not auth.auth_context.forbid_rsa:
                    encoded_public = utils.base64_url_decode(role['public_key'])
                    public_key = crypto.load_rsa_public_key(encoded_public)
                    transfer_key = crypto.encrypt_rsa(auth.auth_context.data_key, public_key)
                    request['transfer_key'] = utils.base64_url_encode(transfer_key)
                auth.execute_auth_command(request)
            return True
        else:
            return False


def logout(context: KeeperParams):
    if context.auth is None:
        return

    logger = utils.get_logger()
    auth_context = context.auth.auth_context
    if auth_context.sso_login_info and auth_context.sso_login_info.idp_session_id:
        sso_url = auth_context.sso_login_info.sso_url
        sp_url_builder = urllib.parse.urlparse(sso_url)
        sp_url_query = urllib.parse.parse_qsl(sp_url_builder.query, keep_blank_values=True)
        session_id = auth_context.sso_login_info.idp_session_id
        if auth_context.sso_login_info.is_cloud:
            sso_rq = ssocloud_pb2.SsoCloudRequest()
            sso_rq.clientVersion = context.auth.keeper_endpoint.client_version
            sso_rq.embedded = True
            sso_rq.username = auth_context.username
            sso_rq.idpSessionId = session_id
            transmission_key = utils.generate_aes_key()
            api_rq = endpoint.prepare_api_request(
                context.auth.keeper_endpoint.server_key_id, transmission_key, sso_rq.SerializeToString(),
                session_token=auth_context.session_token,
                keeper_locale=context.auth.keeper_endpoint.locale or 'en_US')
            sp_url_query.append(('payload', utils.base64_url_encode(api_rq.SerializeToString())))
        else:
            sp_url_query.append(('embedded', ''))
            sp_url_query.append(('token', ''))
            sp_url_query.append(('user', auth_context.username))
            if session_id:
                sp_url_query.append(('session_id', session_id))

        sp_url_builder = sp_url_builder._replace(path=sp_url_builder.path.replace('/login', '/logout'),
                                                 query=urllib.parse.urlencode(sp_url_query, doseq=True))
        sp_url = urllib.parse.urlunparse(sp_url_builder)
        prompt_utils.output_text(FormattedText([('class:h3', 'SSO Logout URL: '), ('', sp_url)]))

    try:
        context.auth.execute_auth_rest('vault/logout_v3', None)
    except Exception as e:
        logger.debug('Logout error: %s', e)
    finally:
        context.clear_session()
