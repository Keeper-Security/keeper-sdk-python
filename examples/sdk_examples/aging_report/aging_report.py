"""Example: Password aging report using Keeper SDK."""

import datetime
import getpass
import sqlite3
import sys
import traceback

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage, aging_report
from keepersdk.errors import KeeperApiError


TABLE_WIDTH = 140
COL_WIDTHS = (30, 30, 25, 10, 45)
HEADERS = ['Owner', 'Title', 'Password Changed', 'Shared', 'Record URL']


def login():
    config = configuration.JsonConfigurationStorage()
    server = config.get().last_server or 'keepersecurity.com'
    
    keeper_endpoint = endpoint.KeeperEndpoint(config, server)
    auth_context = login_auth.LoginAuth(keeper_endpoint)
    auth_context.resume_session = True
    
    username = config.get().last_login
    if not username:
        print("Error: No saved login found. Please run with interactive login first.")
        return None, None
    
    auth_context.login(username)
    
    while not auth_context.login_step.is_final():
        step = auth_context.login_step
        if isinstance(step, login_auth.LoginStepDeviceApproval):
            step.send_push(login_auth.DeviceApprovalChannel.KeeperPush)
            print("Device approval required. Approve and press Enter.")
            input()
        elif isinstance(step, login_auth.LoginStepPassword):
            step.verify_password(getpass.getpass('Enter password: '))
        elif isinstance(step, login_auth.LoginStepTwoFactor):
            channel = step.get_channels()[0]
            code = getpass.getpass(f'Enter 2FA code for {channel.channel_name}: ')
            step.send_code(channel.channel_uid, code)
        else:
            raise NotImplementedError(f"Unsupported login step: {type(step).__name__}")
    
    if isinstance(auth_context.login_step, login_auth.LoginStepConnected):
        return auth_context.login_step.take_keeper_auth(), server
    return None, None


def format_row(values):
    return ' '.join(
        f"{str(val or '')[:w-1]:<{w}}"
        for val, w in zip(values, COL_WIDTHS + (20,) * (len(values) - len(COL_WIDTHS)))
    )


def print_report(rows, title):
    print(f"\n{title}")
    print('=' * TABLE_WIDTH)
    print(format_row(HEADERS))
    print('-' * TABLE_WIDTH)
    
    for row in rows:
        display_row = list(row)
        display_row[3] = 'True' if display_row[3] else 'False'
        print(format_row(display_row))
    
    print('=' * TABLE_WIDTH)
    print(f"\nFound {len(rows)} record(s) with aging passwords")


def generate_report(auth: keeper_auth.KeeperAuth, server: str):
    if not auth.auth_context.is_enterprise_admin:
        print("ERROR: This operation requires enterprise admin privileges.")
        return 1
    
    enterprise = None
    try:
        conn = sqlite3.Connection('file::memory:', uri=True)
        enterprise_id = auth.auth_context.enterprise_id or 0
        storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(lambda: conn, enterprise_id)
        enterprise = enterprise_loader.EnterpriseLoader(auth, storage)
        
        print('\nThe default password aging period is 3 months\n')
        print('Loading record password change information...')
        
        config = aging_report.AgingReportConfig(server=server)
        generator = aging_report.AgingReportGenerator(enterprise.enterprise_data, auth, config)
        rows = list(generator.generate_report_rows())
        
        cutoff_dt = datetime.datetime.now() - datetime.timedelta(days=aging_report.DEFAULT_PERIOD_DAYS)
        title = f'Aging Report: Records With Passwords Last Modified Before {cutoff_dt.strftime("%Y/%m/%d %H:%M:%S")}'
        
        print_report(rows, title)
        return 0
        
    except KeeperApiError as e:
        print(f"API Error: {e}")
        return 1
    except Exception as e:
        print(f"Error generating aging report: {e}")
        traceback.print_exc()
        return 1
    finally:
        if enterprise:
            enterprise.close()
        auth.close()


def main():
    auth, server = login()
    if not auth:
        print("Login failed. Unable to generate aging report.")
        return 1
    return generate_report(auth, server)


if __name__ == "__main__":
    sys.exit(main() or 0)
