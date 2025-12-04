import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage, account_transfer
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


def transfer_user_account(keeper_auth_context):
    """
    Transfer a user account from one user to another.
    
    Args:
        keeper_auth_context: The authenticated Keeper context with enterprise admin privileges.
    """
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        print("Error: You must be an enterprise admin to transfer user accounts")
        keeper_auth_context.close()
        return
    
    try:
        enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
        conn = sqlite3.Connection('file::memory:', uri=True)
        enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(
            lambda: conn,
            enterprise_id
        )
        
        loader = enterprise_loader.EnterpriseLoader(keeper_auth_context, enterprise_storage)
        loader.load()
        
        enterprise_data = loader.enterprise_data
        
        print("\nEnterprise Users:")
        print("-" * 60)
        users = list(enterprise_data.users.get_all_entities())
        for i, user in enumerate(users[:20], 1):
            status = user.status if hasattr(user, 'status') else 'N/A'
            print(f"{i}. {user.username} (ID: {user.enterprise_user_id}, Status: {status})")
        if len(users) > 20:
            print(f"... and {len(users) - 20} more users")
        print("-" * 60)
        
        source_email = input('\nEnter source user email to transfer FROM: ').strip()
        target_email = input('Enter target user email to transfer TO: ').strip()
        
        if not source_email or not target_email:
            print("Both source and target emails are required")
        elif source_email == target_email:
            print("Source and target cannot be the same user")
        else:
            source_user = None
            target_user = None
            for user in users:
                if user.username.lower() == source_email.lower():
                    source_user = user
                if user.username.lower() == target_email.lower():
                    target_user = user
            
            if not source_user:
                print(f"Source user '{source_email}' not found in enterprise")
            elif not target_user:
                print(f"Target user '{target_email}' not found in enterprise")
            else:
                print(f"\nTransfer Details:")
                print(f"  From: {source_user.username} (ID: {source_user.enterprise_user_id})")
                print(f"  To: {target_user.username} (ID: {target_user.enterprise_user_id})")
                print("\nWARNING: This will transfer ALL vault data (records, shared folders,")
                print("teams, user folders) from source user to target user.")
                print("The source user account will be deleted after transfer.")
                
                confirm = input('\nType "TRANSFER" to confirm: ').strip()
                
                if confirm == "TRANSFER":
                    try:
                        target_keys = keeper_auth.UserKeys()
                        
                        transfer_manager = account_transfer.AccountTransferManager(
                            loader,
                            keeper_auth_context
                        )
                        
                        result = transfer_manager.transfer_account(
                            from_username=source_user.username,
                            to_username=target_user.username,
                            target_public_keys=target_keys
                        )
                        
                        print("\n" + "=" * 60)
                        print("TRANSFER COMPLETED")
                        print("=" * 60)
                        print(f"Success: {result.success}")
                        print(f"Records Transferred: {result.records_transferred}")
                        print(f"Shared Folders Transferred: {result.shared_folders_transferred}")
                        print(f"Teams Transferred: {result.teams_transferred}")
                        print(f"User Folders Transferred: {result.user_folders_transferred}")
                        if result.corrupted_records > 0:
                            print(f"Corrupted Records: {result.corrupted_records}")
                        if result.corrupted_shared_folders > 0:
                            print(f"Corrupted Shared Folders: {result.corrupted_shared_folders}")
                        print("=" * 60)
                        
                    except account_transfer.AccountTransferError as e:
                        print(f"\nTransfer Error: {e}")
                    except Exception as e:
                        print(f"\nError during transfer: {e}")
                else:
                    print("Transfer cancelled")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        keeper_auth_context.close()


def main():
    """
    Main entry point for the user transfer script.
    Performs login and manages user account transfers.
    """
    keeper_auth_context = login()
    
    if keeper_auth_context:
        transfer_user_account(keeper_auth_context)
    else:
        print("Login failed. Unable to transfer user accounts.")


if __name__ == "__main__":
    main()
