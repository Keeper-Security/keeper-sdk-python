import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.vault import sqlite_storage, vault_online
from keepersdk.constants import KEEPER_PUBLIC_HOSTS


def login():
    """
    Handle the login process including server selection, authentication,
    and multi-factor authentication steps.
    
    Returns:
        keeper_auth_context: The authenticated Keeper context, or None if login fails.
    """
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
        return login_auth_context.login_step.take_keeper_auth()
    
    return None


def show_breach_status(keeper_auth_context: keeper_auth.KeeperAuth):
    """
    Display BreachWatch status for the vault.
    
    Args:
        keeper_auth_context: The authenticated Keeper context.
    """
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8')
    )
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    vault.sync_down()
    
    print("\nBreachWatch Status")
    print("=" * 100)
    
    if not vault.breach_watch_plugin():
        print("Status: DISABLED")
        print("\nBreachWatch is not enabled for this account.")
        print("Contact your administrator to enable BreachWatch.")
    else:
        print("Status: ENABLED")
        
        breach_watch = vault.breach_watch_plugin().breach_watch
        if not breach_watch:
            print("Scanner: UNAVAILABLE")
            print("\nUnable to initialize BreachWatch scanner.")
        else:
            print("Scanner: READY")
        
        total_records = 0
        breached_records = 0
        secure_records = 0
        
        for record_info in vault.vault_data.records():
            if record_info.version not in (2, 3):
                continue
            
            total_records += 1
            
            bw_record = vault.vault_data.storage.breach_watch_records.get_entity(record_info.record_uid)
            if bw_record:
                breached_records += 1
            else:
                secure_records += 1
        
        print(f"\nVault Statistics:")
        print(f"  Total Records: {total_records}")
        print(f"  Breached Records: {breached_records}")
        print(f"  Secure Records: {secure_records}")
        
        if total_records > 0:
            breach_percentage = (breached_records / total_records) * 100
            print(f"  Breach Percentage: {breach_percentage:.1f}%")
            
            if breached_records > 0:
                print(f"\nWARNING: {breached_records} record(s) with breached passwords detected!")
                print("   Run 'list_breaches.py' to see details and update affected passwords.")
            else:
                print("\nAll passwords are secure! No breaches detected.")
        else:
            print("\n  No records found in vault.")
    
    print("=" * 100)
    
    vault.close()
    keeper_auth_context.close()


def main():
    """
    Main entry point for the breach status script.
    Performs login and displays BreachWatch status.
    """
    keeper_auth_context = login()
    
    if keeper_auth_context:
        show_breach_status(keeper_auth_context)
    else:
        print("Login failed. Unable to show breach status.")


if __name__ == "__main__":
    main()
