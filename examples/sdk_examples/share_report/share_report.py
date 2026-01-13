"""Share Report SDK Example - Demonstrates generating share reports for vault records and folders."""

import getpass
import sqlite3
import traceback
from typing import Optional, List, Tuple

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.vault import share_report, vault_online
from keepersdk.vault.sqlite_storage import SqliteVaultStorage
from keepersdk.errors import KeeperApiError
from keepersdk.constants import KEEPER_PUBLIC_HOSTS


TABLE_WIDTH = 120
RECORD_COL_WIDTHS = (36, 30, 25, 30)
FOLDER_COL_WIDTHS = (25, 30, 25, 25, 30)
SUMMARY_COL_WIDTHS = (40, 15, 20)


def login() -> Optional[keeper_auth.KeeperAuth]:
    """Handle the login process including server selection and authentication."""
    config = configuration.JsonConfigurationStorage()
    server = _get_server(config)
    
    keeper_endpoint = endpoint.KeeperEndpoint(config, server)
    login_auth_context = login_auth.LoginAuth(keeper_endpoint)
    username = config.get().last_login or input('Enter username: ')
    
    login_auth_context.resume_session = True
    login_auth_context.login(username)
    
    logged_in_with_persistent = _complete_login_steps(login_auth_context)
    
    if logged_in_with_persistent:
        print("Successfully logged in with persistent login")
    
    if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
        return login_auth_context.login_step.take_keeper_auth()
    return None


def _get_server(config: configuration.JsonConfigurationStorage) -> str:
    """Get server from config or prompt user."""
    if config.get().last_server:
        return config.get().last_server
    
    print("Available server options:")
    for region, host in KEEPER_PUBLIC_HOSTS.items():
        print(f"  {region}: {host}")
    server = input('Enter server (default: keepersecurity.com): ').strip() or 'keepersecurity.com'
    config.get().last_server = server
    return server


def _complete_login_steps(login_auth_context: login_auth.LoginAuth) -> bool:
    """Complete all login steps, returns True if used persistent login."""
    logged_in_with_persistent = True
    
    while not login_auth_context.login_step.is_final():
        step = login_auth_context.login_step
        
        if isinstance(step, login_auth.LoginStepDeviceApproval):
            step.send_push(login_auth.DeviceApprovalChannel.KeeperPush)
            print("Device approval request sent. Approve this device and press Enter to continue.")
            input()
        elif isinstance(step, login_auth.LoginStepPassword):
            step.verify_password(getpass.getpass('Enter password: '))
        elif isinstance(step, login_auth.LoginStepTwoFactor):
            channel = step.get_channels()[0]
            code = getpass.getpass(f'Enter 2FA code for {channel.channel_name}: ')
            step.send_code(channel.channel_uid, code)
        else:
            raise NotImplementedError(f"Unsupported login step: {type(step).__name__}")
        
        logged_in_with_persistent = False
    
    return logged_in_with_persistent


def format_row(values: List, widths: Tuple) -> str:
    """Format a row of values according to column widths."""
    return ' '.join(
        f"{str(val if val is not None else '')[:w-1]:<{w}}"
        for val, w in zip(values, widths)
    )


def print_table(title: str, headers: List[str], rows: List[List], widths: Tuple, empty_msg: str) -> None:
    """Print a formatted table with headers and rows."""
    print(f"\n{'=' * TABLE_WIDTH}")
    print(title)
    print('=' * TABLE_WIDTH)
    
    if not rows:
        print(empty_msg)
        return
    
    print(format_row(headers, widths))
    print('-' * TABLE_WIDTH)
    for row in rows:
        print(format_row(row, widths))
    print('=' * TABLE_WIDTH)
    print(f"\nTotal: {len(rows)}")


def print_records_report(entries) -> None:
    """Print the share report for records."""
    rows = [
        [e.record_uid, e.record_title or '', e.record_owner or '', e.shared_with_count]
        for e in entries
    ]
    print_table(
        "SHARED RECORDS REPORT",
        ['Record UID', 'Title', 'Owner', 'Shared With Count'],
        rows, RECORD_COL_WIDTHS,
        "No shared records found."
    )


def print_folders_report(entries) -> None:
    """Print the share report for shared folders."""
    rows = [
        [e.folder_uid or '', e.folder_name or '', e.shared_to or '', e.permissions or '', e.folder_path or '']
        for e in entries
    ]
    print_table(
        "SHARED FOLDERS REPORT",
        ['Folder UID', 'Folder Name', 'Shared To', 'Permissions', 'Path'],
        rows, FOLDER_COL_WIDTHS,
        "No shared folders found."
    )


def print_summary_report(entries) -> None:
    """Print the summary report showing shares by target."""
    rows = [
        [e.shared_to or '', e.record_count or '-', e.shared_folder_count or '-']
        for e in entries
    ]
    print_table(
        "SHARE SUMMARY REPORT",
        ['Shared To', 'Records', 'Shared Folders'],
        rows, SUMMARY_COL_WIDTHS,
        "No shares found."
    )


def generate_share_reports(keeper_auth_context: keeper_auth.KeeperAuth) -> None:
    """Generate and display share reports for the vault."""
    vault = None
    try:
        conn = sqlite3.Connection('file::memory:', uri=True)
        vault_owner = bytes(keeper_auth_context.auth_context.username, 'utf-8')
        vault = vault_online.VaultOnline(keeper_auth_context, SqliteVaultStorage(lambda: conn, vault_owner))
        
        print("\nSyncing vault data...")
        vault.sync_down()
        print(f"Vault synced: {vault.vault_data.record_count} records, "
              f"{vault.vault_data.shared_folder_count} shared folders")
        
        _generate_all_reports(vault)
        
    except KeeperApiError as e:
        print(f"\nAPI Error: {e}")
    except Exception as e:
        print(f"\nError generating share reports: {e}")
        traceback.print_exc()
    finally:
        if vault:
            vault.close()
        keeper_auth_context.close()


def _create_report_generator(
    vault: vault_online.VaultOnline,
    *,
    show_ownership: bool = False,
    folders_only: bool = False
) -> share_report.ShareReportGenerator:
    """Create a ShareReportGenerator with the specified configuration.
    
    Args:
        vault: The VaultOnline instance
        show_ownership: Include ownership information in the report
        folders_only: Generate report for shared folders only
        
    Returns:
        Configured ShareReportGenerator instance
    """
    return share_report.ShareReportGenerator(
        vault=vault,
        config=share_report.ShareReportConfig(
            show_ownership=show_ownership,
            folders_only=folders_only,
        ),
    )


def _generate_all_reports(vault: vault_online.VaultOnline) -> None:
    """Generate all three report types."""
    print("\nGenerating shared records report...")
    records_generator = _create_report_generator(vault, show_ownership=True)
    print_records_report(records_generator.generate_records_report())
    
    print("\nGenerating shared folders report...")
    folders_generator = _create_report_generator(vault, folders_only=True)
    print_folders_report(folders_generator.generate_shared_folders_report())
    
    print("\nGenerating share summary report...")
    summary_generator = _create_report_generator(vault)
    print_summary_report(summary_generator.generate_summary_report())


def main() -> None:
    """Main entry point for the share report script."""
    print("=" * 60)
    print("Keeper Vault Share Report Generator")
    print("=" * 60)
    print("\nThis tool generates share reports for records and folders in your Keeper vault.\n")
    
    keeper_auth_context = login()
    if keeper_auth_context:
        generate_share_reports(keeper_auth_context)
    else:
        print("Login failed. Unable to generate share reports.")


if __name__ == "__main__":
    main()

