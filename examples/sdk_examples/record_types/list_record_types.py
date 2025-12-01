import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online
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
    vault.sync_down()
    
    print("\nAvailable Record Types")
    print("=" * 100)
    
    record_types_list = list(vault.vault_data.get_record_types())
    
    if not record_types_list:
        print("\nNo record types found")
        print("Record types are managed at the enterprise level.")
    else:
        print(f"\nFound {len(record_types_list)} record type(s)")
        print("-" * 100)
        print(f"{'ID':<10} {'Name':<40} {'Scope':<15} {'Description':<30}")
        print("-" * 100)
        
        record_types_dict = {}
        for rt in record_types_list:
            rt_id = str(rt.id) if hasattr(rt, 'id') else 'N/A'
            rt_name = rt.name if hasattr(rt, 'name') else 'N/A'
            rt_scope = str(rt.scope) if hasattr(rt, 'scope') else 'N/A'
            rt_desc = (rt.description[:29] if rt.description else '') if hasattr(rt, 'description') else ''
            
            record_types_dict[rt_name.lower()] = rt
            print(f"{rt_id[:9]:<10} {rt_name[:39]:<40} {rt_scope[:14]:<15} {rt_desc:<30}")
        
        print("-" * 100)
        
        rt_name_to_view = input('\nEnter record type name to view details (or press Enter to skip): ').strip()
        
        if rt_name_to_view and rt_name_to_view.lower() in record_types_dict:
            rt = record_types_dict[rt_name_to_view.lower()]
            
            print(f"\nRecord Type Details: {rt.name if hasattr(rt, 'name') else rt_name_to_view}")
            print("=" * 100)
            
            if hasattr(rt, 'id'):
                print(f"ID: {rt.id}")
            if hasattr(rt, 'scope'):
                print(f"Scope: {rt.scope}")
            if hasattr(rt, 'description') and rt.description:
                print(f"Description: {rt.description}")
            
            if hasattr(rt, 'fields') and rt.fields:
                print(f"\nFields ({len(rt.fields)}):")
                print("-" * 100)
                print(f"{'Field Type':<25} {'Label':<30} {'Required':<10}")
                print("-" * 100)
                
                for field in rt.fields:
                    field_type = field.type if hasattr(field, 'type') else 'N/A'
                    field_label = field.label if hasattr(field, 'label') else ''
                    field_required = 'Yes' if (hasattr(field, 'required') and field.required) else 'No'
                    
                    print(f"{field_type[:24]:<25} {field_label[:29]:<30} {field_required:<10}")
            
            print("=" * 100)
    
    print("\n" + "=" * 100)
    
    vault.close()
    keeper_auth_context.close()

