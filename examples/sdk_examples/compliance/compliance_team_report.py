"""
Compliance Team Report SDK Example

Usage: python compliance_team_report.py
"""

import getpass
import logging
import os
import sqlite3
import traceback

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage, compliance
from keepersdk.errors import KeeperApiError
from keepersdk.constants import KEEPER_PUBLIC_HOSTS
from keepersdk.plugins.sox import compliance_storage as cs

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

TABLE_WIDTH = 140
COL_WIDTHS = (30, 24, 35, 20, 10)


def login():
    """Handle login with server selection and authentication."""
    config = configuration.JsonConfigurationStorage()
    
    if not config.get().last_server:
        logger.info("Available server options:")
        for region, host in KEEPER_PUBLIC_HOSTS.items():
            logger.info(f"  {region}: {host}")
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
            logger.info("Device approval request sent. Approve this device and press Enter to continue.")
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
        logger.info("Successfully logged in with persistent login")
    
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


def print_report(rows, headers):
    """Print the team report in table format."""
    logger.info("\n" + "=" * TABLE_WIDTH)
    logger.info("TEAM ACCESS REPORT")
    logger.info("=" * TABLE_WIDTH)
    
    logger.info(format_row([h.replace('_', ' ').title() for h in headers]))
    logger.info("-" * TABLE_WIDTH)
    
    for row in rows:
        logger.info(format_row([str(v) if v is not None else '' for v in row]))
    
    logger.info("=" * TABLE_WIDTH)
    logger.info(f"\nTotal Entries: {len(rows)}")
    
    if rows:
        unique_teams = len(set(r[1] for r in rows if len(r) > 1 and r[1]))
        unique_folders = len(set(r[3] for r in rows if len(r) > 3 and r[3]))
        total_records = sum(r[5] for r in rows if len(r) > 5 and r[5])
        logger.info(f"\nSummary: {unique_teams} teams, {unique_folders} folders, {total_records} records")


def generate_team_report(keeper_auth_context: keeper_auth.KeeperAuth):
    """Generate team access report with SQLite caching."""
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        logger.error("ERROR: Enterprise admin privileges required.")
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
        
        logger.info("\nLoading enterprise data...")
        
        def progress_callback(msg):
            if msg:
                print(f"\r{msg}", end='', flush=True)
        
        config = compliance.ComplianceReportConfig(shared=True, no_rebuild=True, cache_max_age_days=1)
        generator = compliance.ComplianceReportGenerator(
            enterprise.enterprise_data, keeper_auth_context, config,
            compliance_storage=compliance_storage, progress_callback=progress_callback
        )
        
        rows = list(generator.generate_report_rows('team'))
        headers = compliance.ComplianceReportGenerator.get_headers('team')
        print_report(rows, headers)
        
    except KeeperApiError as e:
        logger.error(f"\nAPI Error: {e}")
    except Exception as e:
        logger.error(f"\nError: {e}")
        traceback.print_exc()
    finally:
        if compliance_storage and hasattr(compliance_storage, 'close_connection'):
            compliance_storage.close_connection()
        if enterprise:
            enterprise.close()
        keeper_auth_context.close()


def main():
    logger.info("=" * 60)
    logger.info("Keeper Compliance Team Report")
    logger.info("=" * 60 + "\n")
    
    keeper_auth_context = login()
    if keeper_auth_context:
        generate_team_report(keeper_auth_context)
    else:
        logger.error("Login failed.")


if __name__ == "__main__":
    main()
