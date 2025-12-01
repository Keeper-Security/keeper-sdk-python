import getpass
import logging
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint

logging.getLogger('asyncio').setLevel(logging.CRITICAL)
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
    
    if not vault.breach_watch_plugin():
        print("BreachWatch is not enabled for this account.")
        print("Please contact your administrator to enable BreachWatch.")
    else:
        breach_watch = vault.breach_watch_plugin().breach_watch
        
        if not breach_watch:
            print("Unable to initialize BreachWatch scanner.")
        else:
            passwords_to_scan = []
            
            print("Enter passwords to scan (one per line, empty line to finish):")
            while True:
                pwd = input("Password: ").strip()
                if not pwd:
                    break
                passwords_to_scan.append(pwd)
            
            if not passwords_to_scan:
                print("No passwords provided for scanning.")
            else:
                print(f"\nScanning {len(passwords_to_scan)} password(s)...")
                print("=" * 100)
                
                scan_results = []
                for password, status in breach_watch.scan_passwords(passwords_to_scan):
                    scan_results.append({
                        'password': password,
                        'status': status
                    })
                
                if scan_results:
                    print(f"{'Password':<30} {'Status':<20} {'Details':<50}")
                    print("-" * 100)
                    
                    for result in scan_results:
                        pwd_display = result['password'][:27] + '***' if len(result['password']) > 30 else result['password']
                        status = result['status']
                        
                        if status is None:
                            status_text = "ERROR"
                            details = "Unable to scan password"
                        elif hasattr(status, 'breachDetected') and status.breachDetected:
                            status_text = "BREACHED"
                            details = "This password has been found in a data breach"
                        else:
                            status_text = "SECURE"
                            details = "No breach detected"
                        
                        print(f"{pwd_display:<30} {status_text:<20} {details:<50}")
                    
                    print("-" * 100)
                    breached_count = sum(1 for r in scan_results if r['status'] and hasattr(r['status'], 'breachDetected') and r['status'].breachDetected)
                    secure_count = len(scan_results) - breached_count
                    
                    print(f"\nSummary: {breached_count} breached, {secure_count} secure")
                    if breached_count > 0:
                        print("\nRecommendation: Do not use breached passwords. Choose strong, unique passwords.")
    
    vault.close()
    keeper_auth_context.close()

