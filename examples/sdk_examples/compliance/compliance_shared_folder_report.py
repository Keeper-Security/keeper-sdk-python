"""
Compliance Shared Folder Report SDK Example

Usage: python compliance_shared_folder_report.py
"""

import getpass
import os
import sqlite3
import traceback

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage, compliance
from keepersdk.errors import KeeperApiError
from keepersdk.constants import KEEPER_PUBLIC_HOSTS
from keepersdk.plugins.sox import compliance_storage as cs

TABLE_WIDTH = 180
COL_WIDTHS = (22, 12, 12, 22, 50, 34)


def login():
    """Handle login with server selection and authentication."""
    config = configuration.JsonConfigurationStorage()
    
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
            login_auth_context.login_step.verify_password(getpass.getpass('Enter password: '))
        elif isinstance(login_auth_context.login_step, login_auth.LoginStepTwoFactor):
            channel = login_auth_context.login_step.get_channels()[0]
            login_auth_context.login_step.send_code(channel.channel_uid, getpass.getpass(f'Enter 2FA code for {channel.channel_name}: '))
        else:
            raise NotImplementedError(f"Unsupported login step: {type(login_auth_context.login_step).__name__}")
        logged_in_with_persistent = False
    
    if logged_in_with_persistent:
        print("Successfully logged in with persistent login")
    
    if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
        return login_auth_context.login_step.take_keeper_auth()
    return None


def get_compliance_storage(config_path: str, enterprise_id: int):
    """Create SQLite compliance storage for caching."""
    db_name = cs.get_compliance_database_name(config_path, enterprise_id)
    storage = cs.SqliteComplianceStorage(lambda: cs.get_cached_connection(db_name), enterprise_id)
    storage.database_name = db_name
    storage.close_connection = lambda: cs.close_cached_connection(db_name)
    return storage


def format_row(values, widths=COL_WIDTHS):
    """Format a row of values according to column widths."""
    formatted = []
    for i, val in enumerate(values):
        if i >= len(widths):
            break
        text = str(val if val is not None else '')[:widths[i] - 1]
        formatted.append(f"{text:<{widths[i]}}")
    return ' '.join(formatted)


def flatten_rows(rows):
    """Flatten rows with list values into individual rows (like CLI output)."""
    flattened = []
    for row in rows:
        # row format: (shared_folder_uid, team_uid, team_name, record_uid, record_title, email)
        sf_uid = row[0] if len(row) > 0 else ''
        team_uid = row[1] if len(row) > 1 else ''
        team_name = row[2] if len(row) > 2 else ''
        record_uids = row[3] if len(row) > 3 else []
        record_titles = row[4] if len(row) > 4 else []
        emails = row[5] if len(row) > 5 else []
        
        # Convert to lists if not already
        if not isinstance(record_uids, list):
            record_uids = [record_uids] if record_uids else []
        if not isinstance(record_titles, list):
            record_titles = [record_titles] if record_titles else []
        if not isinstance(emails, list):
            emails = [emails] if emails else []
        if not isinstance(team_uid, list):
            team_uid = [team_uid] if team_uid else []
        if not isinstance(team_name, list):
            team_name = [team_name] if team_name else []
        
        max_rows = max(len(record_uids), len(record_titles), len(emails), 1)
        
        for i in range(max_rows):
            flattened.append((
                sf_uid if i == 0 else '',
                team_uid[0] if team_uid and i == 0 else '',
                team_name[0] if team_name and i == 0 else '',
                record_uids[i] if i < len(record_uids) else '',
                record_titles[i] if i < len(record_titles) else '',
                emails[i] if i < len(emails) else ''
            ))
    return flattened


def print_report(rows, headers):
    """Print the shared folder report in table format."""
    print("\n" + "=" * TABLE_WIDTH)
    print("SHARED FOLDER REPORT")
    print("=" * TABLE_WIDTH)
    
    display_headers = [h.replace('_', ' ').title() for h in headers]
    print(format_row(display_headers))
    print("-" * TABLE_WIDTH)
    
    flattened = flatten_rows(rows)
    for row in flattened:
        print(format_row([str(v) if v else '' for v in row]))
    
    print("=" * TABLE_WIDTH)
    
    unique_folders = len(set(r[0] for r in flattened if r[0]))
    unique_records = len(set(r[3] for r in flattened if r[3]))
    print(f"\nTotal Rows: {len(flattened)}")
    print(f"Summary: {unique_folders} shared folders, {unique_records} records")


def generate_shared_folder_report(keeper_auth_context: keeper_auth.KeeperAuth):
    """Generate shared folder report with SQLite caching."""
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        print("ERROR: Enterprise admin privileges required.")
        keeper_auth_context.close()
        return
    
    enterprise = None
    compliance_storage = None
    
    try:
        conn = sqlite3.Connection('file::memory:', uri=True)
        enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
        enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(lambda: conn, enterprise_id)
        enterprise = enterprise_loader.EnterpriseLoader(keeper_auth_context, enterprise_storage)
        
        config_path = os.path.expanduser('~/.keeper/config.json')
        compliance_storage = get_compliance_storage(config_path, enterprise_id)
        
        print("\nLoading enterprise data...")
        
        def progress_callback(msg):
            if msg:
                print(f"\r{msg}", end='', flush=True)
        
        config = compliance.ComplianceReportConfig(shared=True, no_rebuild=True, cache_max_age_days=1)
        generator = compliance.ComplianceReportGenerator(
            enterprise.enterprise_data, keeper_auth_context, config,
            compliance_storage=compliance_storage, progress_callback=progress_callback
        )
        
        rows = list(generator.generate_report_rows('shared_folder'))
        headers = compliance.ComplianceReportGenerator.get_headers('shared_folder')
        print_report(rows, headers)
        
    except KeeperApiError as e:
        print(f"\nAPI Error: {e}")
    except Exception as e:
        print(f"\nError: {e}")
        traceback.print_exc()
    finally:
        if compliance_storage and hasattr(compliance_storage, 'close_connection'):
            compliance_storage.close_connection()
        if enterprise:
            enterprise.close()
        keeper_auth_context.close()


def main():
    print("=" * 60)
    print("Keeper Compliance Shared Folder Report")
    print("=" * 60 + "\n")
    
    keeper_auth_context = login()
    if keeper_auth_context:
        generate_shared_folder_report(keeper_auth_context)
    else:
        print("Login failed.")


if __name__ == "__main__":
    main()
