import getpass
import sqlite3
from datetime import datetime

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online

config = configuration.JsonConfigurationStorage()
keeper_endpoint = endpoint.KeeperEndpoint(config)
login_auth_context = login_auth.LoginAuth(keeper_endpoint)

username = None
if config.get().users() and config.get().users()[0]:
    username = config.get().users()[0].username
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
        raise NotImplementedError()
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
    
    try:
        rq = {
            'command': 'get_one_time_shares'
        }
        response = keeper_auth_context.execute_auth_command(rq)
        
        shares = response.get('one_time_shares', [])
        
        if not shares:
            print("\nNo one-time shares found")
        else:
            print(f"\nOne-Time Shares ({len(shares)})")
            print("=" * 120)
            print(f"{'Share Name':<30} {'Record Title':<30} {'Created':<25} {'Expires':<25}")
            print("-" * 120)
            
            for share in shares:
                share_uid = share.get('share_uid', 'N/A')
                share_name = share.get('name', 'Unnamed')[:29]
                record_uid = share.get('record_uid', '')
                
                record_title = 'N/A'
                if record_uid:
                    record_info = vault.vault_data.get_record(record_uid)
                    if record_info:
                        record_title = record_info.title[:29]
                
                created_time = share.get('created_time', 0)
                expire_time = share.get('expire_time', 0)
                
                created_str = datetime.fromtimestamp(created_time / 1000).strftime('%Y-%m-%d %H:%M:%S') if created_time else 'N/A'
                expire_str = datetime.fromtimestamp(expire_time / 1000).strftime('%Y-%m-%d %H:%M:%S') if expire_time else 'N/A'
                
                print(f"{share_name:<30} {record_title:<30} {created_str:<25} {expire_str:<25}")
            
            print("-" * 120)
            print(f"Total shares: {len(shares)}")
        
        print("=" * 120)
        
    except Exception as e:
        print(f"Error retrieving one-time shares: {e}")
    
    vault.close()
    keeper_auth_context.close()

