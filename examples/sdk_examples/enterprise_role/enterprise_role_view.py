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


def view_enterprise_roles(keeper_auth_context):
    """
    View enterprise role details with optional search.
    
    Args:
        keeper_auth_context: The authenticated Keeper context with enterprise admin privileges.
    """
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        print("ERROR: This operation requires enterprise admin privileges.")
        print("The current user is not an enterprise administrator.")
        keeper_auth_context.close()
        return
    
    try:
        conn = sqlite3.Connection('file::memory:', uri=True)
        enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
        enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(lambda: conn, enterprise_id)
        
        enterprise = enterprise_loader.EnterpriseLoader(keeper_auth_context, enterprise_storage)
        
        role_search = input('Enter role name or ID (or leave empty for all roles): ').strip()
        
        roles_to_display = []
        
        if role_search:
            for role in enterprise.enterprise_data.roles.get_all_entities():
                role_name = role.name if hasattr(role, 'name') and role.name else ''
                role_id_str = str(role.role_id) if hasattr(role, 'role_id') else ''
                
                if (role_search.lower() in role_name.lower() or 
                    role_search == role_id_str):
                    roles_to_display.append(role)
            
            if not roles_to_display:
                print(f'\nNo roles found matching: "{role_search}"')
        else:
            roles_to_display = list(enterprise.enterprise_data.roles.get_all_entities())
        
        if roles_to_display:
            print("\nEnterprise Role Details")
            print("=" * 120)
            
            for role in roles_to_display:
                role_name = role.name if hasattr(role, 'name') and role.name else 'N/A'
                role_id = str(role.role_id) if hasattr(role, 'role_id') else 'N/A'
                
                node_name = ""
                if hasattr(role, 'node_id') and role.node_id:
                    node = enterprise.enterprise_data.nodes.get_entity(role.node_id)
                    if node:
                        node_name = node.name if hasattr(node, 'name') and node.name else str(role.node_id)
                
                print(f"\nRole Name: {role_name}")
                print(f"Role ID: {role_id}")
                if node_name:
                    print(f"Node: {node_name}")
                
                if hasattr(role, 'visible_below') and role.visible_below:
                    print(f"Visible Below: Yes")
                
                if hasattr(role, 'new_user_inherit') and role.new_user_inherit:
                    print(f"New User Inherit: Yes")
                
                role_users = list(enterprise.enterprise_data.role_users.get_links_by_subject(role.role_id))
                if role_users:
                    print(f"\nUsers ({len(role_users)}):")
                    for role_user in role_users[:10]:
                        user = enterprise.enterprise_data.users.get_entity(role_user.enterprise_user_id)
                        if user:
                            print(f"  - {user.username}")
                    if len(role_users) > 10:
                        print(f"  ... and {len(role_users) - 10} more")
                
                role_teams = list(enterprise.enterprise_data.role_teams.get_links_by_subject(role.role_id))
                if role_teams:
                    print(f"\nTeams ({len(role_teams)}):")
                    for role_team in role_teams[:10]:
                        team = enterprise.enterprise_data.teams.get_entity(role_team.team_uid)
                        if team:
                            team_name = team.name if hasattr(team, 'name') else role_team.team_uid
                            print(f"  - {team_name}")
                    if len(role_teams) > 10:
                        print(f"  ... and {len(role_teams) - 10} more")
                
                role_privileges = list(enterprise.enterprise_data.role_privileges.get_links_by_subject(role.role_id))
                if role_privileges:
                    print(f"\nPrivileges ({len(role_privileges)}):")
                    for priv in role_privileges:
                        if hasattr(priv, 'privilege_type'):
                            print(f"  - {priv.privilege_type}")
                
                print("-" * 120)
            
            print(f"\nTotal roles displayed: {len(roles_to_display)}")
        
        print("=" * 120)
        
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
    Main entry point for the enterprise role view script.
    Performs login and displays enterprise role details.
    """
    keeper_auth_context = login()
    
    if keeper_auth_context:
        view_enterprise_roles(keeper_auth_context)
    else:
        print("Login failed. Unable to retrieve enterprise information.")


if __name__ == "__main__":
    main()
