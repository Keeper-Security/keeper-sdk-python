import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage
from keepersdk.errors import KeeperApiError
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


def display_enterprise_users(keeper_auth_context):
    """
    Load and display enterprise users information.
    
    Args:
        keeper_auth_context: The authenticated Keeper context with enterprise admin privileges.
    """
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        print("ERROR: This operation requires enterprise admin privileges.")
        print("The current user is not an enterprise administrator.")
        print("\nTo use enterprise info features, you need:")
        print("  1. An enterprise account")
        print("  2. Enterprise administrator role")
        keeper_auth_context.close()
        return
    
    try:
        conn = sqlite3.Connection('file::memory:', uri=True)
        enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
        enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(lambda: conn, enterprise_id)
        
        enterprise = enterprise_loader.EnterpriseLoader(keeper_auth_context, enterprise_storage)
        
        print("Enterprise Users Information")
        print("=" * 100)
        print(f"{'Name':<30} {'Email':<35} {'Status':<15} {'Node':<20}")
        print("-" * 100)
        
        for user in enterprise.enterprise_data.users.get_all_entities():
            user_name = user.full_name if hasattr(user, 'full_name') and user.full_name else user.username
            user_email = user.username
            user_status = user.status if hasattr(user, 'status') else 'unknown'
            
            node_name = ""
            if hasattr(user, 'node_id') and user.node_id:
                node = enterprise.enterprise_data.nodes.get_entity(user.node_id)
                if node:
                    node_name = node.name if hasattr(node, 'name') and node.name else str(user.node_id)
            
            print(f"{user_name[:29]:<30} {user_email[:34]:<35} {user_status:<15} {node_name[:19]:<20}")
        
        print("=" * 100)
        
        total_users = len(list(enterprise.enterprise_data.users.get_all_entities()))
        print(f"\nTotal users: {total_users}")
        
        enterprise.close()
        keeper_auth_context.close()
        
    except KeeperApiError as e:
        print(f"\nAPI Error: {e}")
        keeper_auth_context.close()
    except Exception as e:
        print(f"\nError loading enterprise data: {e}")
        keeper_auth_context.close()


def main():
    """
    Main entry point for the enterprise info user script.
    Performs login and displays enterprise users information.
    """
    keeper_auth_context = login()
    
    if keeper_auth_context:
        display_enterprise_users(keeper_auth_context)
    else:
        print("Login failed. Unable to retrieve enterprise information.")


if __name__ == "__main__":
    main()
