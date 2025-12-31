"""
Share Report SDK Example

This example demonstrates how to use the Keeper SDK to generate share reports
for records and shared folders in your vault. The report shows sharing
information including share targets, permissions, and folder details.

Usage:
    python share_report.py

Requirements:
    - Keeper account with shared records
    - Keeper SDK installed

The example demonstrates:
    1. Logging into Keeper
    2. Syncing vault data
    3. Generating share reports for records
    4. Generating share reports for shared folders
    5. Generating summary reports by share target
"""

import getpass
import sqlite3
import traceback
from typing import Optional

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.vault import share_report, vault_online
from keepersdk.vault.sqlite_storage import SqliteVaultStorage
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage
from keepersdk.errors import KeeperApiError
from keepersdk.constants import KEEPER_PUBLIC_HOSTS


# Table formatting constants
TABLE_WIDTH = 120
RECORD_COL_WIDTHS = (36, 30, 25, 30)
FOLDER_COL_WIDTHS = (25, 30, 25, 25, 30)
SUMMARY_COL_WIDTHS = (40, 15, 20)


def login() -> Optional[keeper_auth.KeeperAuth]:
    """
    Handle the login process including server selection, authentication,
    and multi-factor authentication steps.
    
    Returns:
        keeper_auth.KeeperAuth: The authenticated Keeper context, or None if login fails.
    """
    config = configuration.JsonConfigurationStorage()
    
    # Server selection
    if not config.get().last_server:
        print("Available server options:")
        for region, host in KEEPER_PUBLIC_HOSTS.items():
            print(f"  {region}: {host}")
        server = input('Enter server (default: keepersecurity.com): ').strip() or 'keepersecurity.com'
        config.get().last_server = server
    else:
        server = config.get().last_server
    
    keeper_endpoint = endpoint.KeeperEndpoint(config, server)
    login_auth_context = login_auth.LoginAuth(keeper_endpoint)
   
    username = config.get().last_login or input('Enter username: ')
    
    login_auth_context.resume_session = True
    login_auth_context.login(username)
    
    logged_in_with_persistent = True
    
    while not login_auth_context.login_step.is_final():
        if isinstance(login_auth_context.login_step, login_auth.LoginStepDeviceApproval):
            login_auth_context.login_step.send_push(login_auth.DeviceApprovalChannel.KeeperPush)
            print("Device approval request sent. Approve this device and press Enter to continue.")
            input()
        elif isinstance(login_auth_context.login_step, login_auth.LoginStepPassword):
            password = getpass.getpass('Enter password: ')
            login_auth_context.login_step.verify_password(password)
        elif isinstance(login_auth_context.login_step, login_auth.LoginStepTwoFactor):
            channel = login_auth_context.login_step.get_channels()[0]
            code = getpass.getpass(f'Enter 2FA code for {channel.channel_name}: ')
            login_auth_context.login_step.send_code(channel.channel_uid, code)
        else:
            raise NotImplementedError(f"Unsupported login step: {type(login_auth_context.login_step).__name__}")
        logged_in_with_persistent = False
    
    if logged_in_with_persistent:
        print("Successfully logged in with persistent login")
    
    if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
        return login_auth_context.login_step.take_keeper_auth()
    
    return None


def format_row(values, widths):
    """
    Format a row of values according to column widths.
    
    Args:
        values: List of values to format
        widths: Tuple of column widths
        
    Returns:
        str: Formatted row string
    """
    formatted = []
    for i, val in enumerate(values):
        if i >= len(widths):
            break
        width = widths[i]
        text = str(val if val is not None else '')[:width - 1]
        formatted.append(f"{text:<{width}}")
    return ' '.join(formatted)


def print_records_report(entries):
    """
    Print the share report for records in table format.
    
    Args:
        entries: List of ShareReportEntry objects
    """
    print("\n" + "=" * TABLE_WIDTH)
    print("SHARED RECORDS REPORT")
    print("=" * TABLE_WIDTH)
    
    if not entries:
        print("No shared records found.")
        return
    
    headers = ['Record UID', 'Title', 'Owner', 'Shared With Count']
    print(format_row(headers, RECORD_COL_WIDTHS))
    print("-" * TABLE_WIDTH)
    
    for entry in entries:
        row = [
            entry.record_uid,
            entry.record_title[:28] if entry.record_title else '',
            entry.record_owner[:23] if entry.record_owner else '',
            entry.shared_with_count
        ]
        print(format_row(row, RECORD_COL_WIDTHS))
    
    print("=" * TABLE_WIDTH)
    print(f"\nTotal Shared Records: {len(entries)}")


def print_folders_report(entries):
    """
    Print the share report for shared folders in table format.
    
    Args:
        entries: List of SharedFolderReportEntry objects
    """
    print("\n" + "=" * TABLE_WIDTH)
    print("SHARED FOLDERS REPORT")
    print("=" * TABLE_WIDTH)
    
    if not entries:
        print("No shared folders found.")
        return
    
    headers = ['Folder UID', 'Folder Name', 'Shared To', 'Permissions', 'Path']
    print(format_row(headers, FOLDER_COL_WIDTHS))
    print("-" * TABLE_WIDTH)
    
    for entry in entries:
        row = [
            entry.folder_uid[:23] if entry.folder_uid else '',
            entry.folder_name[:28] if entry.folder_name else '',
            entry.shared_to[:23] if entry.shared_to else '',
            entry.permissions[:23] if entry.permissions else '',
            entry.folder_path[:28] if entry.folder_path else ''
        ]
        print(format_row(row, FOLDER_COL_WIDTHS))
    
    print("=" * TABLE_WIDTH)
    print(f"\nTotal Shared Folder Entries: {len(entries)}")


def print_summary_report(entries):
    """
    Print the summary report showing shares by target.
    
    Args:
        entries: List of ShareSummaryEntry objects
    """
    print("\n" + "=" * TABLE_WIDTH)
    print("SHARE SUMMARY REPORT")
    print("=" * TABLE_WIDTH)
    
    if not entries:
        print("No shares found.")
        return
    
    headers = ['Shared To', 'Records', 'Shared Folders']
    print(format_row(headers, SUMMARY_COL_WIDTHS))
    print("-" * TABLE_WIDTH)
    
    for entry in entries:
        row = [
            entry.shared_to[:38] if entry.shared_to else '',
            entry.record_count if entry.record_count else '-',
            entry.shared_folder_count if entry.shared_folder_count else '-'
        ]
        print(format_row(row, SUMMARY_COL_WIDTHS))
    
    print("=" * TABLE_WIDTH)
    print(f"\nTotal Share Targets: {len(entries)}")


def generate_share_reports(keeper_auth_context: keeper_auth.KeeperAuth):
    """
    Generate share reports for the vault.
    
    This function syncs the vault, generates multiple types of share reports,
    and displays the results.
    
    Args:
        keeper_auth_context: The authenticated Keeper context.
    """
    vault = None
    try:
        # Create vault storage and online vault
        conn = sqlite3.Connection('file::memory:', uri=True)
        vault_storage = SqliteVaultStorage(lambda: conn)
        vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
        
        print("\nSyncing vault data...")
        vault.sync_down()
        
        # Count records
        record_count = vault.vault_data.record_count
        shared_folder_count = vault.vault_data.shared_folder_count
        print(f"Vault synced: {record_count} records, {shared_folder_count} shared folders")
        
        # Generate Records Report
        print("\nGenerating shared records report...")
        records_config = share_report.ShareReportConfig(
            show_ownership=True,
            verbose=False
        )
        records_generator = share_report.ShareReportGenerator(
            vault=vault,
            config=records_config
        )
        record_entries = records_generator.generate_records_report()
        print_records_report(record_entries)
        
        # Generate Shared Folders Report
        print("\nGenerating shared folders report...")
        folders_config = share_report.ShareReportConfig(
            folders_only=True
        )
        folders_generator = share_report.ShareReportGenerator(
            vault=vault,
            config=folders_config
        )
        folder_entries = folders_generator.generate_shared_folders_report()
        print_folders_report(folder_entries)
        
        # Generate Summary Report
        print("\nGenerating share summary report...")
        summary_config = share_report.ShareReportConfig()
        summary_generator = share_report.ShareReportGenerator(
            vault=vault,
            config=summary_config
        )
        summary_entries = summary_generator.generate_summary_report()
        print_summary_report(summary_entries)
        
    except KeeperApiError as e:
        print(f"\nAPI Error: {e}")
    except Exception as e:
        print(f"\nError generating share reports: {e}")
        traceback.print_exc()
    finally:
        if vault:
            vault.close()
        keeper_auth_context.close()


def main():
    """
    Main entry point for the share report script.
    Performs login and generates share reports.
    """
    print("=" * 60)
    print("Keeper Vault Share Report Generator")
    print("=" * 60)
    print("\nThis tool generates share reports for records and folders")
    print("in your Keeper vault.\n")
    
    keeper_auth_context = login()
    
    if keeper_auth_context:
        generate_share_reports(keeper_auth_context)
    else:
        print("Login failed. Unable to generate share reports.")


if __name__ == "__main__":
    main()

