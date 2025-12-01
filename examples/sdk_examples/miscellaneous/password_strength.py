import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_record
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
    
    print("Password Strength Report")
    print("=" * 120)
    
    password_stats = {
        'weak': [],
        'medium': [],
        'strong': []
    }
    
    for record_info in vault.vault_data.records():
        if record_info.version not in (2, 3):
            continue
        
        record = vault.vault_data.load_record(record_info.record_uid)
        
        passwords = []
        if isinstance(record, vault_record.PasswordRecord):
            if record.password:
                passwords.append(record.password)
        elif isinstance(record, vault_record.TypedRecord):
            for field in record.fields:
                if field.field_type == 'password' and field.value:
                    pwd = field.value[0] if isinstance(field.value, list) else field.value
                    if pwd:
                        passwords.append(pwd)
        
        for password in passwords:
            score = utils.password_score(password)
            
            record_data = {
                'uid': record_info.record_uid,
                'title': record_info.title,
                'score': score
            }
            
            if score < 40:
                password_stats['weak'].append(record_data)
            elif score < 70:
                password_stats['medium'].append(record_data)
            else:
                password_stats['strong'].append(record_data)
    
    total_records = len(password_stats['weak']) + len(password_stats['medium']) + len(password_stats['strong'])
    
    if total_records == 0:
        print("\nNo records with passwords found in vault")
    else:
        print(f"\nTotal Records with Passwords: {total_records}")
        print(f"  Strong Passwords (70-100): {len(password_stats['strong'])}")
        print(f"  Medium Passwords (40-69): {len(password_stats['medium'])}")
        print(f"  Weak Passwords (0-39): {len(password_stats['weak'])}")
        
        if password_stats['weak']:
            print(f"\n⚠️  Weak Passwords ({len(password_stats['weak'])} records)")
            print("-" * 120)
            print(f"{'Title':<50} {'Record UID':<40} {'Score':<15}")
            print("-" * 120)
            
            for rec in password_stats['weak'][:10]:
                title = rec['title'][:49] if rec['title'] else '(Untitled)'
                uid = rec['uid'][:39]
                score = rec['score']
                print(f"{title:<50} {uid:<40} {score:<15}")
            
            if len(password_stats['weak']) > 10:
                print(f"  ... and {len(password_stats['weak']) - 10} more")
            
            print("\nRecommendation: Update weak passwords immediately!")
        
        if password_stats['medium']:
            print(f"\n⚡ Medium Passwords ({len(password_stats['medium'])} records)")
            print("   Consider strengthening these passwords")
        
        if password_stats['strong']:
            print(f"\n✓ Strong Passwords ({len(password_stats['strong'])} records)")
            print("   These passwords are secure")
    
    print("=" * 120)
    
    vault.close()
    keeper_auth_context.close()

