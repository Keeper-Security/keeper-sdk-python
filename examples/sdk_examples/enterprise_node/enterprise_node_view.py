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
            
            node_search = input('Enter node name or ID (or leave empty for all nodes): ').strip()
            
            nodes_to_display = []
            
            if node_search:
                for node in enterprise.enterprise_data.nodes.get_all():
                    node_name = node.display_name if hasattr(node, 'display_name') and node.display_name else node.name if hasattr(node, 'name') else ''
                    node_id_str = str(node.node_id) if hasattr(node, 'node_id') else ''
                    
                    if (node_search.lower() in node_name.lower() or 
                        node_search == node_id_str):
                        nodes_to_display.append(node)
                
                if not nodes_to_display:
                    print(f'\nNo nodes found matching: "{node_search}"')
            else:
                nodes_to_display = list(enterprise.enterprise_data.nodes.get_all())
            
            if nodes_to_display:
                print("\nEnterprise Node Details")
                print("=" * 120)
                
                for node in nodes_to_display:
                    node_name = node.display_name if hasattr(node, 'display_name') and node.display_name else node.name if hasattr(node, 'name') else 'N/A'
                    node_id = str(node.node_id) if hasattr(node, 'node_id') else 'N/A'
                    
                    parent_name = ""
                    if hasattr(node, 'parent_id') and node.parent_id:
                        parent_node = enterprise.enterprise_data.nodes.get_entity(node.parent_id)
                        if parent_node:
                            parent_name = parent_node.display_name if hasattr(parent_node, 'display_name') and parent_node.display_name else parent_node.name if hasattr(parent_node, 'name') else str(node.parent_id)
                    
                    user_count = sum(1 for user in enterprise.enterprise_data.users.get_all() 
                                     if hasattr(user, 'node_id') and user.node_id == node.node_id)
                    team_count = sum(1 for team in enterprise.enterprise_data.teams.get_all() 
                                     if hasattr(team, 'node_id') and team.node_id == node.node_id)
                    role_count = sum(1 for role in enterprise.enterprise_data.roles.get_all() 
                                     if hasattr(role, 'node_id') and role.node_id == node.node_id)
                    
                    print(f"\nNode Name: {node_name}")
                    print(f"Node ID: {node_id}")
                    if parent_name:
                        print(f"Parent Node: {parent_name}")
                    print(f"Users: {user_count}")
                    print(f"Teams: {team_count}")
                    print(f"Roles: {role_count}")
                    
                    if hasattr(node, 'license_id') and node.license_id:
                        print(f"License ID: {node.license_id}")
                    
                    print("-" * 120)
                
                print(f"\nTotal nodes displayed: {len(nodes_to_display)}")
            
            print("=" * 120)
            
            enterprise.close()
            keeper_auth_context.close()
            
        except KeeperApiError as e:
            print(f"\nAPI Error: {e}")
            keeper_auth_context.close()
        except Exception as e:
            print(f"\nError loading enterprise data: {e}")
            keeper_auth_context.close()

