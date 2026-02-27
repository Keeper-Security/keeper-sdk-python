import getpass
import json
import logging
import sqlite3
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
from keepersdk.vault import sqlite_storage, vault_online, vault_record

try:
    import pyperclip
except ImportError:
    pyperclip = None


logger = utils.get_logger()
logger.setLevel(logging.WARNING)


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

    def run(self) -> Optional[keeper_auth.KeeperAuth]:
        """
        Run the login flow.

        Returns:
            Authenticated Keeper context, or None if login fails.
        """
        server = self._ensure_server()
        keeper_endpoint = endpoint.KeeperEndpoint(self._config, server)
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


def list_records(keeper_auth_context: keeper_auth.KeeperAuth) -> None:
    """
    List all records in the vault.

    Args:
        keeper_auth_context: The authenticated Keeper context.
    """
    conn = sqlite3.Connection("file::memory:", uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth_context.auth_context.username, "utf-8"),
    )

    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    vault.sync_down()

    print("Vault Records:")
    print("-" * 50)
    for record in vault.vault_data.records():
        print(f"Title: {record.title}")

        if record.version == 2:
            legacy_record = vault.vault_data.load_record(record.record_uid)
            if isinstance(legacy_record, vault_record.PasswordRecord):
                print(f"Username: {legacy_record.login}")
                print(f"URL: {legacy_record.link}")

        elif record.version >= 3:
            print(f"Record Type: {record.record_type}")

        print("-" * 50)

    vault.close()
    keeper_auth_context.close()


def main() -> None:
    """Run login and list all vault records."""
    login_flow = LoginFlow()
    keeper_auth_context = login_flow.run()

    if keeper_auth_context:
        list_records(keeper_auth_context)
    else:
        print("Login failed. Unable to list records.")


if __name__ == "__main__":
    main()

