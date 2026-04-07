"""
Sample script demonstrating update_record_permissions from share_management_utils.

Updates record-level permissions (can_edit / can_share) for records in a folder,
either for direct record shares, shared folder record permissions, or both.
Uses the same login and vault setup pattern as share_folder.py.
"""
import getpass
import json
import logging
import sqlite3
from typing import Any, Dict, Optional

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
from keepersdk.vault import share_management_utils, sqlite_storage, vault_online

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
            elif isinstance(step, login_auth.LoginStepTwoFactor):
                self._handle_two_factor(step)
            elif isinstance(step, login_auth.LoginStepPassword):
                self._handle_password(step)
            elif isinstance(step, login_auth.LoginStepSsoToken):
                self._handle_sso_token(step)
            elif isinstance(step, login_auth.LoginStepSsoDataKey):
                self._handle_sso_data_key(step)
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
        menu = [
            ("email_send", "to send email"),
            ("email_code=<code>", "to validate verification code sent via email"),
            ("keeper_push", "to send Keeper Push notification"),
            ("2fa_send", "to send 2FA code"),
            ("2fa_code=<code>", "to validate a code provided by 2FA application"),
            ("<Enter>", "to resume"),
        ]
        lines = ["Approve by selecting a method below"]
        lines.extend(f"  {cmd} {desc}" for cmd, desc in menu)
        print("\n".join(lines))
        selection = input("Type your selection or <Enter> to resume: ").strip()
        if selection is None:
            return
        if selection in ("email_send", "es"):
            step.send_push(channel=login_auth.DeviceApprovalChannel.Email)
            print("An email with instructions has been sent. Press <Enter> when approved.")
        elif selection.startswith("email_code="):
            code = selection[len("email_code=") :]
            step.send_code(channel=login_auth.DeviceApprovalChannel.Email, code=code)
            print("Successfully verified email code.")
        elif selection in ("keeper_push", "kp"):
            step.send_push(channel=login_auth.DeviceApprovalChannel.KeeperPush)
            print(
                "Successfully made a push notification to the approved device. "
                "Press <Enter> when approved."
            )
        elif selection in ("2fa_send", "2fs"):
            step.send_push(channel=login_auth.DeviceApprovalChannel.TwoFactor)
            print("2FA code was sent.")
        elif selection.startswith("2fa_code="):
            code = selection[len("2fa_code=") :]
            step.send_code(channel=login_auth.DeviceApprovalChannel.TwoFactor, code=code)
            print("Successfully verified 2FA code.")
        else:
            step.resume()

    def _handle_password(self, step: login_auth.LoginStepPassword) -> None:
        print(f"\nEnter password for {step.username}")
        while True:
            password = getpass.getpass("Password: ")
            if not password:
                raise KeyboardInterrupt()
            try:
                step.verify_password(password)
                break
            except errors.KeeperApiError as kae:
                print(
                    "Invalid email or password combination, please re-enter."
                    if kae.result_code == "auth_failed"
                    else kae.message
                )

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
    """Enable persistent login and register data key for device."""
    keeper_auth.set_user_setting(keeper_auth_context, 'persistent_login', '1')
    keeper_auth.register_data_key_for_device(keeper_auth_context)
    mins_per_day = 60 * 24
    timeout_in_minutes = mins_per_day * 30
    keeper_auth.set_user_setting(keeper_auth_context, 'logout_timer', str(timeout_in_minutes))
    print("Persistent login turned on successfully and device registered")


def login():
    """
    Handle the login process. Returns (keeper_auth_context, keeper_endpoint) on success,
    or (None, None) if login fails.
    """
    flow = LoginFlow()
    keeper_auth_context = flow.run()
    if keeper_auth_context and not flow.logged_in_with_persistent:
        enable_persistent_login(keeper_auth_context)
    keeper_endpoint = flow.endpoint if keeper_auth_context else None
    return keeper_auth_context, keeper_endpoint


def update_record_permissions_in_folder(
    keeper_auth_context: keeper_auth.KeeperAuth,
    action: str,
    can_share: bool = False,
    can_edit: bool = False,
    folder_uid_or_path: Optional[str] = None,
    recursive: bool = False,
    share_record: bool = True,
    share_folder: bool = True,
    dry_run: bool = False,
    sync_after: bool = True,
) -> Dict[str, Any]:
    """
    Update record permissions (can_edit / can_share) in a folder using
    share_management_utils.update_record_permissions.

    Args:
        keeper_auth_context: Authenticated Keeper context.
        action: 'grant' or 'revoke'.
        can_share: Whether to change the "can share" permission.
        can_edit: Whether to change the "can edit" permission.
        folder_uid_or_path: Folder UID or path; None or empty = root.
        recursive: If True, include all subfolders.
        share_record: If True, update direct record shares.
        share_folder: If True, update shared folder record permissions.
        dry_run: If True, only compute and return planned updates; do not apply.
        sync_after: If True and changes were applied, sync vault down after updates.

    Returns:
        Result dict from update_record_permissions (direct_share_updates,
        shared_folder_updates, direct_share_errors, shared_folder_errors,
        skipped_shared_folders).
    """
    conn = sqlite3.Connection("file::memory:", uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8')
    )
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    vault.sync_down()

    try:
        result = share_management_utils.update_record_permissions(
            vault=vault,
            action=action,
            can_share=can_share,
            can_edit=can_edit,
            folder_uid_or_path=folder_uid_or_path,
            recursive=recursive,
            share_record=share_record,
            share_folder=share_folder,
            dry_run=dry_run,
            sync_after=sync_after,
        )
        _print_result(result, action, dry_run)
        return result
    except share_management_utils.ShareValidationError as e:
        print(f"Validation error: {e}")
        raise
    except share_management_utils.ShareNotFoundError as e:
        print(f"Folder not found: {e}")
        raise
    finally:
        vault.close()
        keeper_auth_context.close()


def _print_result(result: Dict[str, Any], action: str, dry_run: bool) -> None:
    """Print a summary of update_record_permissions result."""
    prefix = "[dry run] " if dry_run else ""
    direct = result.get("direct_share_updates") or []
    sf_updates = result.get("shared_folder_updates") or {}
    direct_errors = result.get("direct_share_errors") or []
    sf_errors = result.get("shared_folder_errors") or []
    skipped = result.get("skipped_shared_folders") or {}

    if direct:
        print(f"{prefix}Direct share updates: {len(direct)}")
    if sf_updates:
        total_sf = sum(len(v) for v in sf_updates.values())
        print(f"{prefix}Shared folder record updates: {total_sf} (across {len(sf_updates)} shared folder(s))")
    if not direct and not sf_updates and not direct_errors and not sf_errors:
        print(f"{prefix}No permission changes to apply for action={action!r}.")
    if direct_errors:
        print(f"Direct share errors: {len(direct_errors)}")
    if sf_errors:
        print(f"Shared folder errors: {len(sf_errors)}")
    if skipped:
        print(f"Skipped shared folders (permissions): {len(skipped)}")


def main() -> None:
    """
    Main entry point. Logs in and updates record permissions in a folder.
    Edit the variables below to match your folder and desired permissions.
    """
    keeper_auth_context, _ = login()
    if not keeper_auth_context:
        print("Login failed. Unable to update record permissions.")
        return

    # Configure these for your run:
    action = "grant"  # or "revoke"
    can_share = True
    can_edit = True
    folder_uid_or_path = "My Folder"  # Use folder UID / path like "My Folder"
    recursive = False
    share_record = True  # update direct record shares
    share_folder = True  # update shared folder record permissions
    dry_run = False  # set to False to apply changes

    update_record_permissions_in_folder(
        keeper_auth_context=keeper_auth_context,
        action=action,
        can_share=can_share,
        can_edit=can_edit,
        folder_uid_or_path=folder_uid_or_path,
        recursive=recursive,
        share_record=share_record,
        share_folder=share_folder,
        dry_run=dry_run,
        sync_after=not dry_run,
    )
    if dry_run:
        print("Run with dry_run=False to apply the changes.")


if __name__ == "__main__":
    main()
