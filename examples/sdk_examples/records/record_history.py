import getpass
import sqlite3
from datetime import datetime

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online
from keepersdk import utils
from keepersdk.constants import KEEPER_PUBLIC_HOSTS

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

username = None
if config.get().last_login:
    username = config.get().last_login
if not username:
    username = input('Enter username: ')
login_auth_context.resume_session = True
login_auth_context.login(username)

logged_in_with_persistent = True
while not login_auth_context.login_step.is_final():
    if isinstance(login_auth_context.login_step, login_auth.LoginStepDeviceApproval):
        login_auth_context.login_step.send_push(login_auth.DeviceApprovalChannel.KeeperPush)
        print("Device approval request sent. Login to existing vault/console or ask admin to approve this device and then press return/enter to resume")
        input()
    elif isinstance(login_auth_context.login_step, login_auth.LoginStepPassword):
        password = getpass.getpass('Enter password: ')
        login_auth_context.login_step.verify_password(password)
    elif isinstance(login_auth_context.login_step, login_auth.LoginStepTwoFactor):
        channel = login_auth_context.login_step.get_channels()[0]
        code = getpass.getpass(f'Enter 2FA code for {channel.channel_name}: ')
        login_auth_context.login_step.send_code(channel.channel_uid, code)
    else:
        raise NotImplementedError(f"Unsupported login step type: {type(login_auth_context.login_step).__name__}")
    logged_in_with_persistent = False

if logged_in_with_persistent:
    print("Successfully logged in with persistent login")

if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
    keeper_auth_context = login_auth_context.login_step.take_keeper_auth()
    
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8')
    )
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    
    record_search = input('Enter record title or UID to view history: ').strip()
    
    if not record_search:
        print("Record identifier cannot be empty")
    else:
        record_found = None
        
        for record_info in vault.vault_data.records():
            if (record_search.lower() in record_info.title.lower() or 
                record_search == record_info.record_uid):
                record_found = record_info
                break
        
        if not record_found:
            print(f"Record '{record_search}' not found")
        else:
            try:
                current_rec = vault.vault_data._records[record_found.record_uid]
                record_key = current_rec.record_key
                
                request = {
                    'command': 'get_record_history',
                    'record_uid': record_found.record_uid,
                    'client_time': utils.current_milli_time()
                }
                
                response = keeper_auth_context.execute_auth_command(request)
                history = response.get('history', [])
                
                if not history:
                    print(f"\nNo history found for record: {record_found.title}")
                else:
                    history.sort(key=lambda x: x.get('revision', 0), reverse=True)
                    
                    print(f"\nRecord History for: {record_found.title}")
                    print(f"Record UID: {record_found.record_uid}")
                    print("=" * 120)
                    print(f"{'Version':<15} {'Modified By':<35} {'Modified Time':<30} {'Revision':<15}")
                    print("-" * 120)
                    
                    length = len(history)
                    for i, version in enumerate(history):
                        version_label = 'Current' if i == 0 else f'V.{length - i}'
                        
                        modified_by = version.get('user_name', 'Unknown')[:34]
                        
                        modified_time = version.get('client_modified_time', 0)
                        if modified_time:
                            dt = datetime.fromtimestamp(modified_time / 1000.0)
                            time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            time_str = 'N/A'
                        
                        revision = version.get('revision', 'N/A')
                        
                        print(f"{version_label:<15} {modified_by:<35} {time_str:<30} {revision:<15}")
                    
                    print("-" * 120)
                    print(f"Total revisions: {length}")
                    print("\nNote: Use the revision number to restore to a previous version.")
                    print("=" * 120)
                
            except Exception as e:
                print(f"Error loading record history: {e}")
    
    vault.close()
    keeper_auth_context.close()

