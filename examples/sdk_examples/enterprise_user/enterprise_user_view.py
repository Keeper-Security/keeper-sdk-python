import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage
from keepersdk.errors import KeeperApiError

config = configuration.JsonConfigurationStorage()
keeper_endpoint = endpoint.KeeperEndpoint(config, keeper_server="dev.keepersecurity.com")
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
    
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        print("ERROR: This operation requires enterprise admin privileges.")
        print("The current user is not an enterprise administrator.")
        keeper_auth_context.close()
    else:
        try:
            conn = sqlite3.Connection('file::memory:', uri=True)
            enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
            enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(lambda: conn, enterprise_id)
            
            enterprise = enterprise_loader.EnterpriseLoader(keeper_auth_context, enterprise_storage)
            
            user_search = input('Enter user email or ID (or leave empty for all users): ').strip()
            
            users_to_display = []
            
            if user_search:
                for user in enterprise.enterprise_data.users.get_all():
                    user_email = user.username if hasattr(user, 'username') else ''
                    user_id_str = str(user.user_id) if hasattr(user, 'user_id') else ''
                    
                    if (user_search.lower() in user_email.lower() or 
                        user_search == user_id_str):
                        users_to_display.append(user)
                
                if not users_to_display:
                    print(f'\nNo users found matching: "{user_search}"')
            else:
                users_to_display = list(enterprise.enterprise_data.users.get_all())
            
            if users_to_display:
                print("\nEnterprise User Details")
                print("=" * 120)
                
                for user in users_to_display:
                    user_name = user.display_name if hasattr(user, 'display_name') and user.display_name else user.username
                    user_email = user.username if hasattr(user, 'username') else 'N/A'
                    user_id = str(user.user_id) if hasattr(user, 'user_id') else 'N/A'
                    user_status = user.status.name if hasattr(user, 'status') else 'unknown'
                    
                    node_name = ""
                    if hasattr(user, 'node_id') and user.node_id:
                        node = enterprise.enterprise_data.nodes.get_entity(user.node_id)
                        if node:
                            node_name = node.display_name if hasattr(node, 'display_name') and node.display_name else str(user.node_id)
                    
                    print(f"\nUser Name: {user_name}")
                    print(f"Email: {user_email}")
                    print(f"User ID: {user_id}")
                    print(f"Status: {user_status}")
                    if node_name:
                        print(f"Node: {node_name}")
                    
                    if hasattr(user, 'account_share_expiration') and user.account_share_expiration:
                        print(f"Account Share Expiration: {user.account_share_expiration}")
                    
                    user_teams = [tu for tu in enterprise.enterprise_data.team_users.get_links_by_object(user.user_id)]
                    if user_teams:
                        print(f"\nTeams ({len(user_teams)}):")
                        for team_user in user_teams[:10]:
                            team = enterprise.enterprise_data.teams.get_entity(team_user.team_uid)
                            if team:
                                team_name = team.name if hasattr(team, 'name') else team_user.team_uid
                                print(f"  - {team_name}")
                        if len(user_teams) > 10:
                            print(f"  ... and {len(user_teams) - 10} more")
                    
                    user_roles = [ru for ru in enterprise.enterprise_data.role_users.get_links_by_object(user.user_id)]
                    if user_roles:
                        print(f"\nRoles ({len(user_roles)}):")
                        for role_user in user_roles[:10]:
                            role = enterprise.enterprise_data.roles.get_entity(role_user.role_id)
                            if role:
                                role_name = role.display_name if hasattr(role, 'display_name') and role.display_name else str(role_user.role_id)
                                print(f"  - {role_name}")
                        if len(user_roles) > 10:
                            print(f"  ... and {len(user_roles) - 10} more")
                    
                    print("-" * 120)
                
                print(f"\nTotal users displayed: {len(users_to_display)}")
            
            print("=" * 120)
            
            enterprise.close()
            keeper_auth_context.close()
            
        except KeeperApiError as e:
            print(f"\nAPI Error: {e}")
            keeper_auth_context.close()
        except Exception as e:
            print(f"\nError loading enterprise data: {e}")
            keeper_auth_context.close()

