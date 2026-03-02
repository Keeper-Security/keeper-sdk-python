import getpass
import sqlite3
import json
import logging
from typing import Dict, Optional

import fido2
import webbrowser

from keepersdk import errors, utils
from keepersdk.authentication import (
    configuration,
    endpoint,
    keeper_auth,
    login_auth,
)
from keepersdk.authentication.yubikey import (
    IKeeperUserInteraction,
    yubikey_authenticate,
)
from keepersdk.constants import KEEPER_PUBLIC_HOSTS
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage
from keepersdk.errors import KeeperApiError

try:
    import pyperclip
except ImportError:
    pyperclip = None

logger = utils.get_logger()
logger.setLevel(logging.INFO)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setLevel(logging.INFO)
    _handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    )
    logger.addHandler(_handler)


class FidoCliInteraction(fido2.client.UserInteraction, IKeeperUserInteraction):
    def output_text(self, text: str) -> None:
        print(text)

    def prompt_up(self) -> None:
        print(
            "\nTouch the flashing Security key to authenticate or "
            "press Ctrl-C to resume with the primary two factor authentication..."
        )

    def request_pin(self, permissions, rd_id):
        return getpass.getpass("Enter Security Key PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


# Two-factor duration codes (used by LoginFlow)
_TWO_FACTOR_DURATION_CODES: Dict[login_auth.TwoFactorDuration, str] = {
    login_auth.TwoFactorDuration.EveryLogin: "login",
    login_auth.TwoFactorDuration.Every12Hours: "12_hours",
    login_auth.TwoFactorDuration.EveryDay: "24_hours",
    login_auth.TwoFactorDuration.Every30Days: "30_days",
    login_auth.TwoFactorDuration.Forever: "forever",
}


class LoginFlow:
    """
    Handles the full login process: server selection, username, password,
    device approval, 2FA, SSO data key, and SSO token.
    """

    def __init__(self) -> None:
        self._config = configuration.JsonConfigurationStorage()
        self._logged_in_with_persistent = True
        self._endpoint: Optional[endpoint.KeeperEndpoint] = None

    @property
    def endpoint(self) -> Optional[endpoint.KeeperEndpoint]:
        return self._endpoint

    @property
    def logged_in_with_persistent(self) -> bool:
        """True if login succeeded by resuming an existing persistent session (no step loop)."""
        return self._logged_in_with_persistent

    def run(self) -> Optional[keeper_auth.KeeperAuth]:
        """
        Run the login flow.

        Returns:
            Authenticated Keeper context, or None if login fails.
        """
        server = self._ensure_server()
        keeper_endpoint = endpoint.KeeperEndpoint(self._config, server)
        self._endpoint = keeper_endpoint
        login_auth_context = login_auth.LoginAuth(keeper_endpoint)

        username = self._config.get().last_login or input("Enter username: ")
        login_auth_context.resume_session = True
        login_auth_context.login(username)

        while not login_auth_context.login_step.is_final():
            step = login_auth_context.login_step
            if isinstance(step, login_auth.LoginStepDeviceApproval):
                self._handle_device_approval(step)
            elif isinstance(step, login_auth.LoginStepPassword):
                self._handle_password(step)
            elif isinstance(step, login_auth.LoginStepTwoFactor):
                self._handle_two_factor(step)
            elif isinstance(step, login_auth.LoginStepSsoDataKey):
                self._handle_sso_data_key(step)
            elif isinstance(step, login_auth.LoginStepSsoToken):
                self._handle_sso_token(step)
            elif isinstance(step, login_auth.LoginStepError):
                print(f"Login error: ({step.code}) {step.message}")
                return None
            else:
                raise NotImplementedError(
                    f"Unsupported login step type: {type(step).__name__}"
                )
            self._logged_in_with_persistent = False

        if self._logged_in_with_persistent:
            print("Successfully logged in with persistent login")

        if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
            return login_auth_context.login_step.take_keeper_auth()

        return None

    def _ensure_server(self) -> str:
        if not self._config.get().last_server:
            print("Available server options:")
            for region, host in KEEPER_PUBLIC_HOSTS.items():
                print(f"  {region}: {host}")
            server = (
                input("Enter server (default: keepersecurity.com): ").strip()
                or "keepersecurity.com"
            )
            self._config.get().last_server = server
        else:
            server = self._config.get().last_server
        return server

    def _handle_device_approval(
        self, step: login_auth.LoginStepDeviceApproval
    ) -> None:
        step.send_push(login_auth.DeviceApprovalChannel.KeeperPush)
        print(
            "Device approval request sent. Login to existing vault/console or "
            "ask admin to approve this device and then press return/enter to resume"
        )
        input()
        step.resume()

    def _handle_password(self, step: login_auth.LoginStepPassword) -> None:
        password = getpass.getpass("Enter password: ")
        step.verify_password(password)

    def _handle_two_factor(self, step: login_auth.LoginStepTwoFactor) -> None:
        channels = [
            x
            for x in step.get_channels()
            if x.channel_type != login_auth.TwoFactorChannel.Other
        ]
        menu = []
        for i, channel in enumerate(channels):
            desc = self._two_factor_channel_desc(channel.channel_type)
            menu.append(
                (
                    str(i + 1),
                    f"{desc} {channel.channel_name} {channel.phone}",
                )
            )
        menu.append(("q", "Quit authentication attempt and return to Commander prompt."))

        lines = ["", "This account requires 2FA Authentication"]
        lines.extend(f"  {a}. {t}" for a, t in menu)
        print("\n".join(lines))

        while True:
            selection = input("Selection: ")
            if selection is None:
                return
            if selection in ("q", "Q"):
                raise KeyboardInterrupt()
            try:
                assert selection.isnumeric()
                idx = 1 if not selection else int(selection)
                assert 1 <= idx <= len(channels)
                channel = channels[idx - 1]
                desc = self._two_factor_channel_desc(channel.channel_type)
                print(f"Selected {idx}. {desc}")
            except AssertionError:
                print(
                    "Invalid entry, additional factors of authentication shown "
                    "may be configured if not currently enabled."
                )
                continue

            if channel.channel_type in (
                login_auth.TwoFactorChannel.TextMessage,
                login_auth.TwoFactorChannel.KeeperDNA,
                login_auth.TwoFactorChannel.DuoSecurity,
            ):
                action = next(
                    (
                        x
                        for x in step.get_channel_push_actions(channel.channel_uid)
                        if x
                        in (
                            login_auth.TwoFactorPushAction.TextMessage,
                            login_auth.TwoFactorPushAction.KeeperDna,
                        )
                    ),
                    None,
                )
                if action:
                    step.send_push(channel.channel_uid, action)

            if channel.channel_type == login_auth.TwoFactorChannel.SecurityKey:
                try:
                    challenge = json.loads(channel.challenge)
                    signature = yubikey_authenticate(challenge, FidoCliInteraction())
                    if signature:
                        print("Verified Security Key.")
                        step.send_code(channel.channel_uid, signature)
                        return
                except Exception as e:
                    logger.error(e)
                continue

            # 2FA code path
            step.duration = min(step.duration, channel.max_expiration)
            available_dura = sorted(
                x for x in _TWO_FACTOR_DURATION_CODES if x <= channel.max_expiration
            )
            available_codes = [
                _TWO_FACTOR_DURATION_CODES.get(x) or "login" for x in available_dura
            ]

            while True:
                mfa_desc = self._two_factor_duration_desc(step.duration)
                prompt_exp = (
                    f"\n2FA Code Duration: {mfa_desc}.\n"
                    f"To change duration: 2fa_duration={'|'.join(available_codes)}"
                )
                print(prompt_exp)

                selection = input("\nEnter 2FA Code or Duration: ")
                if not selection:
                    return
                if selection in available_codes:
                    step.duration = self._two_factor_code_to_duration(selection)
                elif selection.startswith("2fa_duration="):
                    code = selection[len("2fa_duration=") :]
                    if code in available_codes:
                        step.duration = self._two_factor_code_to_duration(code)
                    else:
                        print(f"Invalid 2FA duration: {code}")
                else:
                    try:
                        step.send_code(channel.channel_uid, selection)
                        print("Successfully verified 2FA Code.")
                        return
                    except errors.KeeperApiError as kae:
                        print(f"Invalid 2FA code: ({kae.result_code}) {kae.message}")

    def _handle_sso_data_key(
        self, step: login_auth.LoginStepSsoDataKey
    ) -> None:
        menu = [
            ("1", "Keeper Push. Send a push notification to your device."),
            ("2", "Admin Approval. Request your admin to approve this device."),
            ("r", "Resume SSO authentication after device is approved."),
            ("q", "Quit SSO authentication attempt and return to Commander prompt."),
        ]
        lines = ["Approve this device by selecting a method below:"]
        lines.extend(f"  {cmd:>3}. {text}" for cmd, text in menu)
        print("\n".join(lines))

        while True:
            answer = input("Selection: ")
            if answer is None:
                return
            if answer == "q":
                raise KeyboardInterrupt()
            if answer == "r":
                step.resume()
                break
            if answer in ("1", "2"):
                step.request_data_key(
                    login_auth.DataKeyShareChannel.KeeperPush
                    if answer == "1"
                    else login_auth.DataKeyShareChannel.AdminApproval
                )
            else:
                print(f'Action "{answer}" is not supported.')

    def _handle_sso_token(self, step: login_auth.LoginStepSsoToken) -> None:
        menu = [
            ("a", "SSO User with a Master Password."),
        ]
        if pyperclip:
            menu.append(("c", "Copy SSO Login URL to clipboard."))
        else:
            menu.append(("u", "Show SSO Login URL."))
        try:
            wb = webbrowser.get()
            menu.append(("o", "Navigate to SSO Login URL with the default web browser."))
        except Exception:
            wb = None
        if pyperclip:
            menu.append(("p", "Paste SSO Token from clipboard."))
        menu.append(("t", "Enter SSO Token manually."))
        menu.append(("q", "Quit SSO authentication attempt and return to Commander prompt."))

        lines = [
            "",
            "SSO Login URL:",
            step.sso_login_url,
            "Navigate to SSO Login URL with your browser and complete authentication.",
            "Copy a returned SSO Token into clipboard."
            + (" Paste that token into Commander." if pyperclip else " Then use option 't' to enter the token manually."),
            'NOTE: To copy SSO Token please click "Copy authentication token" '
            'button on "SSO Connect" page.',
            "",
        ]
        lines.extend(f"  {a:>3}. {t}" for a, t in menu)
        print("\n".join(lines))

        while True:
            token = input("Selection: ")
            if token == "q":
                raise KeyboardInterrupt()
            if token == "a":
                step.login_with_password()
                return
            if token == "c":
                token = None
                if pyperclip:
                    try:
                        pyperclip.copy(step.sso_login_url)
                        print("SSO Login URL is copied to clipboard.")
                    except Exception:
                        print("Failed to copy SSO Login URL to clipboard.")
                else:
                    print("Clipboard not available (install pyperclip).")
            elif token == "u":
                token = None
                if not pyperclip:
                    print("\nSSO Login URL:", step.sso_login_url, "\n")
                else:
                    print("Unsupported menu option (use 'c' to copy URL).")
            elif token == "o":
                token = None
                if wb:
                    try:
                        wb.open_new_tab(step.sso_login_url)
                    except Exception:
                        print("Failed to open web browser.")
            elif token == "p":
                if pyperclip:
                    try:
                        token = pyperclip.paste()
                    except Exception:
                        token = ""
                        print("Failed to paste from clipboard")
                else:
                    token = None
                    print("Clipboard not available (use 't' to enter token manually).")
            elif token == "t":
                token = getpass.getpass("Enter SSO Token: ").strip()
            else:
                if len(token) < 10:
                    print(f"Unsupported menu option: {token}")
                    continue

            if token:
                try:
                    step.set_sso_token(token)
                    break
                except errors.KeeperApiError as kae:
                    print(f"SSO Login error: ({kae.result_code}) {kae.message}")

    @staticmethod
    def _two_factor_channel_desc(
        channel_type: login_auth.TwoFactorChannel,
    ) -> str:
        return {
            login_auth.TwoFactorChannel.Authenticator: "TOTP (Google and Microsoft Authenticator)",
            login_auth.TwoFactorChannel.TextMessage: "Send SMS Code",
            login_auth.TwoFactorChannel.DuoSecurity: "DUO",
            login_auth.TwoFactorChannel.RSASecurID: "RSA SecurID",
            login_auth.TwoFactorChannel.SecurityKey: "WebAuthN (FIDO2 Security Key)",
            login_auth.TwoFactorChannel.KeeperDNA: "Keeper DNA (Watch)",
            login_auth.TwoFactorChannel.Backup: "Backup Code",
        }.get(channel_type, "Not Supported")

    @staticmethod
    def _two_factor_duration_desc(
        duration: login_auth.TwoFactorDuration,
    ) -> str:
        return {
            login_auth.TwoFactorDuration.EveryLogin: "Require Every Login",
            login_auth.TwoFactorDuration.Forever: "Save on this Device Forever",
            login_auth.TwoFactorDuration.Every12Hours: "Ask Every 12 hours",
            login_auth.TwoFactorDuration.EveryDay: "Ask Every 24 hours",
            login_auth.TwoFactorDuration.Every30Days: "Ask Every 30 days",
        }.get(duration, "Require Every Login")

    @staticmethod
    def _two_factor_code_to_duration(
        text: str,
    ) -> login_auth.TwoFactorDuration:
        for dura, code in _TWO_FACTOR_DURATION_CODES.items():
            if code == text:
                return dura
        return login_auth.TwoFactorDuration.EveryLogin


def enable_persistent_login(keeper_auth_context: keeper_auth.KeeperAuth) -> None:
    """
    Enable persistent login and register data key for device.
    Sets persistent_login to on and logout_timer to 30 days.
    """
    keeper_auth.set_user_setting(keeper_auth_context, 'persistent_login', '1')
    keeper_auth.register_data_key_for_device(keeper_auth_context)
    mins_per_day = 60 * 24
    timeout_in_minutes = mins_per_day * 30  # 30 days
    keeper_auth.set_user_setting(keeper_auth_context, 'logout_timer', str(timeout_in_minutes))
    print("Persistent login turned on successfully and device registered")


def login():
    """
    Handle the login process including server selection, authentication,
    and multi-factor authentication steps (device approval, password, 2FA
    with channel selection and Security Key, SSO data key, SSO token).

    Returns:
        tuple: (keeper_auth_context, keeper_endpoint) on success, or (None, None) if login fails.
    """
    flow = LoginFlow()
    keeper_auth_context = flow.run()
    if keeper_auth_context and not flow.logged_in_with_persistent:
        enable_persistent_login(keeper_auth_context)
    keeper_endpoint = flow.endpoint if keeper_auth_context else None
    return keeper_auth_context, keeper_endpoint


def view_enterprise_roles(keeper_auth_context: keeper_auth.KeeperAuth):
    """
    View enterprise role details with optional search.
    
    Args:
        keeper_auth_context: The authenticated Keeper context with enterprise admin privileges.
    """
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        print("ERROR: This operation requires enterprise admin privileges.")
        print("The current user is not an enterprise administrator.")
        keeper_auth_context.close()
        return
    
    try:
        conn = sqlite3.Connection('file::memory:', uri=True)
        enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
        enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(lambda: conn, enterprise_id)
        
        enterprise = enterprise_loader.EnterpriseLoader(keeper_auth_context, enterprise_storage)
        
        role_search = input('Enter role name or ID (or leave empty for all roles): ').strip()
        
        roles_to_display = []
        
        if role_search:
            for role in enterprise.enterprise_data.roles.get_all_entities():
                role_name = role.name if hasattr(role, 'name') and role.name else ''
                role_id_str = str(role.role_id) if hasattr(role, 'role_id') else ''
                
                if (role_search.lower() in role_name.lower() or 
                    role_search == role_id_str):
                    roles_to_display.append(role)
            
            if not roles_to_display:
                print(f'\nNo roles found matching: "{role_search}"')
        else:
            roles_to_display = list(enterprise.enterprise_data.roles.get_all_entities())
        
        if roles_to_display:
            print("\nEnterprise Role Details")
            print("=" * 120)
            
            for role in roles_to_display:
                role_name = role.name if hasattr(role, 'name') and role.name else 'N/A'
                role_id = str(role.role_id) if hasattr(role, 'role_id') else 'N/A'
                
                node_name = ""
                if hasattr(role, 'node_id') and role.node_id:
                    node = enterprise.enterprise_data.nodes.get_entity(role.node_id)
                    if node:
                        node_name = node.name if hasattr(node, 'name') and node.name else str(role.node_id)
                
                print(f"\nRole Name: {role_name}")
                print(f"Role ID: {role_id}")
                if node_name:
                    print(f"Node: {node_name}")
                
                if hasattr(role, 'visible_below') and role.visible_below:
                    print(f"Visible Below: Yes")
                
                if hasattr(role, 'new_user_inherit') and role.new_user_inherit:
                    print(f"New User Inherit: Yes")
                
                role_users = list(enterprise.enterprise_data.role_users.get_links_by_subject(role.role_id))
                if role_users:
                    print(f"\nUsers ({len(role_users)}):")
                    for role_user in role_users[:10]:
                        user = enterprise.enterprise_data.users.get_entity(role_user.enterprise_user_id)
                        if user:
                            print(f"  - {user.username}")
                    if len(role_users) > 10:
                        print(f"  ... and {len(role_users) - 10} more")
                
                role_teams = list(enterprise.enterprise_data.role_teams.get_links_by_subject(role.role_id))
                if role_teams:
                    print(f"\nTeams ({len(role_teams)}):")
                    for role_team in role_teams[:10]:
                        team = enterprise.enterprise_data.teams.get_entity(role_team.team_uid)
                        if team:
                            team_name = team.name if hasattr(team, 'name') else role_team.team_uid
                            print(f"  - {team_name}")
                    if len(role_teams) > 10:
                        print(f"  ... and {len(role_teams) - 10} more")
                
                role_privileges = list(enterprise.enterprise_data.role_privileges.get_links_by_subject(role.role_id))
                if role_privileges:
                    print(f"\nPrivileges ({len(role_privileges)}):")
                    for priv in role_privileges:
                        priv_set = priv.to_set()
                        for priv_type in priv_set:
                            print(f"  - {priv_type}")
                
                print("-" * 120)
            
            print(f"\nTotal roles displayed: {len(roles_to_display)}")
        
        print("=" * 120)
        
        enterprise.close()
        keeper_auth_context.close()
        
    except KeeperApiError as e:
        print(f"\nAPI Error: {e}")
        keeper_auth_context.close()
    except Exception as e:
        print(f"\nError loading enterprise data: {e}")
        keeper_auth_context.close()


def main():
    """
    Main entry point for the enterprise role view script.
    Performs login and displays enterprise role details.
    """
    keeper_auth_context, _ = login()
    
    if keeper_auth_context:
        view_enterprise_roles(keeper_auth_context)
    else:
        print("Login failed. Unable to retrieve enterprise information.")


if __name__ == "__main__":
    main()
