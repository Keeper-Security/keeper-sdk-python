import getpass
import sqlite3
import traceback

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage, aging_report
from keepersdk.errors import KeeperApiError
from keepersdk.constants import KEEPER_PUBLIC_HOSTS


TABLE_WIDTH = 140
COL_WIDTHS = (30, 30, 25, 10, 45)


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
        return login_auth_context.login_step.take_keeper_auth(), server
    
    return None, None


def format_row(values):
    """Format a row of values according to column widths."""
    formatted = []
    for i, val in enumerate(values):
        width = COL_WIDTHS[i] if i < len(COL_WIDTHS) else 20
        text = str(val or '')[:width - 1]
        formatted.append(f"{text:<{width}}")
    return ' '.join(formatted)


def print_report(rows, cutoff_date):
    """Print the aging report in table format."""
    print("\n" + "=" * TABLE_WIDTH)
    print(f"PASSWORD AGING REPORT - Records with passwords not changed since {cutoff_date}")
    print("=" * TABLE_WIDTH)
    
    headers = ['Owner', 'Title', 'Password Changed', 'Shared', 'Record URL']
    print(format_row(headers))
    print("-" * TABLE_WIDTH)
    
    for row in rows:
        # Format for display - row format is [owner, title, pw_changed_str, shared, url, sf_uid]
        display_row = list(row)
        display_row[3] = 'True' if display_row[3] else 'False'  # shared boolean
        print(format_row(display_row[:5]))  # Only first 5 columns
    
    print("=" * TABLE_WIDTH)
    print(f"\nTotal Records with Aging Passwords: {len(rows)}")


def generate_aging_report_example(keeper_auth_context: keeper_auth.KeeperAuth, server: str):
    """Generate enterprise password aging report."""
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
        
        # Get configuration options
        print("\n" + "=" * 60)
        print("PASSWORD AGING REPORT OPTIONS")
        print("=" * 60)
        print("\nPeriod format: 10d (10 days), 3m (3 months), 1y (1 year)")
        print("Date format: YYYY-MM-DD (e.g., 2024-01-01)")
        print("-" * 60)
        
        period_input = input('\nEnter period or cutoff date (default 3m): ').strip() or '3m'
        rebuild = input('Rebuild cache? (y/N): ').strip().lower() == 'y'
        username = input('Filter by username (leave empty for all): ').strip() or None
        exclude_deleted = input('Exclude deleted records? (y/N): ').strip().lower() == 'y'
        in_shared_folder = input('Only records in shared folders? (y/N): ').strip().lower() == 'y'
        
        period_days = aging_report.DEFAULT_PERIOD_DAYS
        cutoff_date = None
        
        # Try parsing as date first
        parsed_date = aging_report.parse_date(period_input)
        if parsed_date:
            cutoff_date = parsed_date
            cutoff_str = cutoff_date.strftime('%Y-%m-%d')
        else:
            # Try parsing as period
            parsed_days = aging_report.parse_period(period_input)
            if parsed_days:
                period_days = parsed_days
            import datetime
            cutoff_dt = datetime.datetime.now() - datetime.timedelta(days=period_days)
            cutoff_str = cutoff_dt.strftime('%Y-%m-%d')
        
        config = aging_report.AgingReportConfig(
            period_days=period_days,
            cutoff_date=cutoff_date,
            username=username,
            exclude_deleted=exclude_deleted,
            in_shared_folder=in_shared_folder,
            rebuild=rebuild,
            server=server
        )
        
        print(f"\nGenerating aging report for passwords not changed since {cutoff_str}...")
        if rebuild:
            print("Rebuilding record database...")
        
        generator = aging_report.AgingReportGenerator(
            enterprise.enterprise_data,
            keeper_auth_context,
            config
        )
        
        rows = list(generator.generate_report_rows())
        print_report(rows, cutoff_str)
        
    except KeeperApiError as e:
        print(f"\nAPI Error: {e}")
    except Exception as e:
        print(f"\nError generating aging report: {e}")
        traceback.print_exc()
    finally:
        if enterprise:
            enterprise.close()
        keeper_auth_context.close()


def main():
    """Main entry point for the aging report script."""
    print("=" * 60)
    print("Keeper Enterprise Password Aging Report Generator")
    print("=" * 60)
    print("\nThis report shows records with passwords that have not been")
    print("changed within a specified period.")
    print("-" * 60)
    
    keeper_auth_context, server = login()
    
    if keeper_auth_context:
        generate_aging_report_example(keeper_auth_context, server)
    else:
        print("Login failed. Unable to generate aging report.")


if __name__ == "__main__":
    main()
