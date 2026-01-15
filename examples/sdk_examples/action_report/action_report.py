"""Enterprise Action Report SDK Example."""

import getpass
import sqlite3

from keepersdk.authentication import configuration, endpoint, keeper_auth, login_auth
from keepersdk.constants import KEEPER_PUBLIC_HOSTS
from keepersdk.enterprise import action_report, enterprise_loader, sqlite_enterprise_storage
from keepersdk.errors import KeeperApiError

TARGET_STATUS = 'no-logon'
DAYS_SINCE = 30


def login():
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
    
    while not login_auth_context.login_step.is_final():
        step = login_auth_context.login_step
        if isinstance(step, login_auth.LoginStepDeviceApproval):
            step.send_push(login_auth.DeviceApprovalChannel.KeeperPush)
            print("Device approval request sent. Approve this device and press Enter.")
            input()
        elif isinstance(step, login_auth.LoginStepPassword):
            step.verify_password(getpass.getpass('Enter password: '))
        elif isinstance(step, login_auth.LoginStepTwoFactor):
            channel = step.get_channels()[0]
            step.send_code(channel.channel_uid, getpass.getpass(f'Enter 2FA code for {channel.channel_name}: '))
        else:
            raise NotImplementedError(f"Unsupported login step: {type(step).__name__}")
    
    if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
        return login_auth_context.login_step.take_keeper_auth()
    return None


def print_report(entries, target_status, days_since):
    action_text = (
        '\tCOMMAND: NONE (No action specified)\n'
        '\tSTATUS: n/a\n'
        '\tSERVER MESSAGE: n/a\n'
        '\tAFFECTED: 0'
    )
    status_display = target_status[0].upper() + target_status[1:]
    
    print(f'\nAdmin Action Taken:\n{action_text}\n')
    print('Note: the following reflects data prior to any administrative action being applied')
    print(f'{len(entries)} User(s) With "{status_display}" Status Older Than {days_since} Day(s):\n')
    
    if not entries:
        return
    
    headers = ['User ID', 'Email', 'Name', 'Status', 'Transfer Status', 'Node']
    col_widths = [14, 31, 22, 8, 17, 19]
    
    print('  '.join(f'{h:<{w}}' for h, w in zip(headers, col_widths)))
    print('  '.join('-' * w for w in col_widths))
    
    for entry in entries:
        row = [
            str(entry.enterprise_user_id), entry.email, entry.full_name,
            entry.status, entry.transfer_status, entry.node_path
        ]
        print('  '.join(f'{str(v)[:w]:<{w}}' for v, w in zip(row, col_widths)))


def generate_action_report(keeper_auth_context: keeper_auth.KeeperAuth):
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        print("ERROR: This operation requires enterprise admin privileges.")
        keeper_auth_context.close()
        return
    
    enterprise = None
    try:
        conn = sqlite3.Connection('file::memory:', uri=True)
        enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
        storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(lambda: conn, enterprise_id)
        enterprise = enterprise_loader.EnterpriseLoader(keeper_auth_context, storage)
        
        config = action_report.ActionReportConfig(
            target_user_status=TARGET_STATUS,
            days_since=DAYS_SINCE
        )
        generator = action_report.ActionReportGenerator(
            enterprise.enterprise_data, keeper_auth_context, loader=enterprise, config=config
        )
        entries = generator.generate_report()
        print_report(entries, TARGET_STATUS, DAYS_SINCE)
        
    except KeeperApiError as e:
        print(f"\nAPI Error: {e}")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        if enterprise:
            enterprise.close()
        keeper_auth_context.close()


def main():
    auth = login()
    if auth:
        generate_action_report(auth)
    else:
        print("Login failed.")


if __name__ == "__main__":
    main()
