import getpass
import sqlite3
import traceback

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage, user_report
from keepersdk.errors import KeeperApiError
from keepersdk.constants import KEEPER_PUBLIC_HOSTS


TABLE_WIDTH = 140
COL_WIDTHS = (35, 20, 10, 15, 25, 25, 30, 30) 


def login():
    """Handle login with server selection, authentication, and MFA."""
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


def format_row(values):
    """Format a row of values according to column widths."""
    formatted = []
    for i, val in enumerate(values):
        width = COL_WIDTHS[i]
        if isinstance(val, list):
            val = ', '.join(val)
        text = str(val or '')[:width - 1]
        formatted.append(f"{text:<{width}}")
    return ' '.join(formatted)


def print_report(rows):
    """Print the user report in table format."""
    print("\n" + "=" * TABLE_WIDTH)
    print("ENTERPRISE USER REPORT")
    print("=" * TABLE_WIDTH)
    
    headers = ['Email', 'Name', 'Status', 'Transfer', 'Last Login', 'Node', 'Roles', 'Teams']
    print(format_row(headers))
    print("-" * TABLE_WIDTH)
    
    for row in rows:
        print(format_row(row))
    
    print("=" * TABLE_WIDTH)
    print(f"\nTotal Users: {len(rows)}")


def generate_user_report(keeper_auth_context: keeper_auth.KeeperAuth):
    """Generate enterprise user report with details, roles, teams, and last login."""
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        print("ERROR: This operation requires enterprise admin privileges.")
        keeper_auth_context.close()
        return
    
    enterprise = None
    try:
        conn = sqlite3.Connection('file::memory:', uri=True)
        enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
        enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(lambda: conn, enterprise_id)
        enterprise = enterprise_loader.EnterpriseLoader(keeper_auth_context, enterprise_storage)
        
        print("\nLoading enterprise data...")
        
        lookback_input = input('Days to look back for last login (default 365, 0 for all): ').strip()
        lookback_days = int(lookback_input) if lookback_input else 365
        
        config = user_report.UserReportConfig(
            lookback_days=lookback_days,
            include_last_login=True,
            include_roles=True,
            include_teams=True,
            simplified_report=False
        )
        
        print("Generating user report...")
        generator = user_report.UserReportGenerator(
            enterprise.enterprise_data,
            keeper_auth_context,
            config
        )
        
        rows = list(generator.generate_report_rows())
        print_report(rows)
        
    except KeeperApiError as e:
        print(f"\nAPI Error: {e}")
    except Exception as e:
        print(f"\nError generating user report: {e}")
        traceback.print_exc()
    finally:
        if enterprise:
            enterprise.close()
        keeper_auth_context.close()


def main():
    """Main entry point for the user report script."""
    print("=" * 60)
    print("Keeper Enterprise User Report Generator")
    print("=" * 60)
    
    keeper_auth_context = login()
    
    if keeper_auth_context:
        generate_user_report(keeper_auth_context)
    else:
        print("Login failed. Unable to generate user report.")


if __name__ == "__main__":
    main()
