"""Shared Records Report SDK Example - Generates a report of shared records.

Usage:
    python shared_records_report.py
"""

import getpass
import sqlite3
import traceback
from typing import Optional, List

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.vault import shared_records_report, vault_online
from keepersdk.vault.sqlite_storage import SqliteVaultStorage
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage
from keepersdk.errors import KeeperApiError
from keepersdk.constants import KEEPER_PUBLIC_HOSTS


def login() -> Optional[keeper_auth.KeeperAuth]:
    """Handle login with persistent session support."""
    config = configuration.JsonConfigurationStorage()
    
    if not config.get().last_server:
        print("Available server options:")
        for region, host in KEEPER_PUBLIC_HOSTS.items():
            print(f"  {region}: {host}")
        server = input('Enter server (default: keepersecurity.com): ').strip() or 'keepersecurity.com'
        config.get().last_server = server
    
    keeper_endpoint = endpoint.KeeperEndpoint(config, config.get().last_server)
    login_auth_context = login_auth.LoginAuth(keeper_endpoint)
    username = config.get().last_login or input('Enter username: ')
    
    login_auth_context.resume_session = True
    login_auth_context.login(username)
    
    while not login_auth_context.login_step.is_final():
        step = login_auth_context.login_step
        if isinstance(step, login_auth.LoginStepDeviceApproval):
            step.send_push(login_auth.DeviceApprovalChannel.KeeperPush)
            print("Device approval request sent. Approve and press Enter.")
            input()
        elif isinstance(step, login_auth.LoginStepPassword):
            step.verify_password(getpass.getpass('Enter password: '))
        elif isinstance(step, login_auth.LoginStepTwoFactor):
            channel = step.get_channels()[0]
            step.send_code(channel.channel_uid, getpass.getpass(f'Enter 2FA code: '))
        else:
            raise NotImplementedError(f"Unsupported: {type(step).__name__}")
    
    if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
        return login_auth_context.login_step.take_keeper_auth()
    return None


def print_report(entries: List[shared_records_report.SharedRecordReportEntry]) -> None:
    """Print the shared records report in table format."""
    if not entries:
        print("No shared records found.")
        return
    
    # Headers and column widths
    headers = ['#', 'Record UID', 'Title', 'Share Type', 'Shared To', 'Permissions', 'Folder Path']
    widths = [4, 24, 28, 20, 28, 18, 30]
    
    # Print header
    header_row = '  '.join(f"{h:<{w}}" for h, w in zip(headers, widths))
    print(header_row)
    print('-' * len(header_row))
    
    # Print rows
    for i, e in enumerate(entries, 1):
        row = [
            str(i),
            e.record_uid[:22] + '..' if len(e.record_uid) > 24 else e.record_uid,
            e.title[:26] + '..' if len(e.title) > 28 else e.title,
            e.share_type,
            e.shared_to[:26] + '..' if len(e.shared_to) > 28 else e.shared_to,
            e.permissions,
            e.folder_path.replace('\n', ' | ')[:28] + '..' if len(e.folder_path) > 30 else e.folder_path.replace('\n', ' | ')
        ]
        print('  '.join(f"{v:<{w}}" for v, w in zip(row, widths)))


def main() -> None:
    """Main entry point."""
    vault = None
    enterprise = None
    keeper_auth_context = None
    
    try:
        keeper_auth_context = login()
        if not keeper_auth_context:
            print("Login failed.")
            return
        
        # Initialize vault
        vault_conn = sqlite3.Connection('file::memory:', uri=True)
        vault_owner = bytes(keeper_auth_context.auth_context.username, 'utf-8')
        vault = vault_online.VaultOnline(
            keeper_auth_context, 
            SqliteVaultStorage(lambda: vault_conn, vault_owner)
        )
        vault.sync_down()
        
        # Initialize enterprise data if admin (for team expansion)
        enterprise_data = None
        if keeper_auth_context.auth_context.is_enterprise_admin:
            enterprise_conn = sqlite3.Connection('file::memory:', uri=True)
            enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
            enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(
                lambda: enterprise_conn, enterprise_id
            )
            enterprise = enterprise_loader.EnterpriseLoader(keeper_auth_context, enterprise_storage)
            enterprise_data = enterprise.enterprise_data
        
        # Generate report (default: owned records only)
        config = shared_records_report.SharedRecordsReportConfig(
            show_team_users=False,
            all_records=False
        )
        
        generator = shared_records_report.SharedRecordsReportGenerator(
            vault=vault,
            enterprise=enterprise_data,
            auth=keeper_auth_context,
            config=config
        )
        
        entries = generator.generate_report()
        print_report(entries)
        
    except KeeperApiError as e:
        print(f"API Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
    finally:
        if enterprise:
            enterprise.close()
        if vault:
            vault.close()
        if keeper_auth_context:
            keeper_auth_context.close()


if __name__ == "__main__":
    main()
