import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage
from keepersdk.errors import KeeperApiError
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
            
            team_search = input('Enter team name or UID (or leave empty for all teams): ').strip()
            
            teams_to_display = []
            
            if team_search:
                for team in enterprise.enterprise_data.teams.get_all_entities():
                    team_name = team.name if hasattr(team, 'name') and team.name else ''
                    team_uid = team.team_uid if hasattr(team, 'team_uid') else ''
                    
                    if (team_search.lower() in team_name.lower() or 
                        team_search == team_uid):
                        teams_to_display.append(team)
                
                if not teams_to_display:
                    print(f'\nNo teams found matching: "{team_search}"')
            else:
                teams_to_display = list(enterprise.enterprise_data.teams.get_all_entities())
            
            if teams_to_display:
                print("\nEnterprise Team Details")
                print("=" * 120)
                
                for team in teams_to_display:
                    team_name = team.name if hasattr(team, 'name') and team.name else 'N/A'
                    team_uid = team.team_uid if hasattr(team, 'team_uid') else 'N/A'
                    
                    node_name = ""
                    if hasattr(team, 'node_id') and team.node_id:
                        node = enterprise.enterprise_data.nodes.get_entity(team.node_id)
                        if node:
                            node_name = node.display_name if hasattr(node, 'display_name') and node.display_name else str(team.node_id)
                    
                    user_count = len(list(enterprise.enterprise_data.team_users.get_links_by_subject(team_uid)))
                    
                    print(f"\nTeam Name: {team_name}")
                    print(f"Team UID: {team_uid}")
                    if node_name:
                        print(f"Node: {node_name}")
                    print(f"User Count: {user_count}")
                    
                    if hasattr(team, 'restrict_edit'):
                        print(f"Restrict Edit: {team.restrict_edit}")
                    if hasattr(team, 'restrict_share'):
                        print(f"Restrict Share: {team.restrict_share}")
                    if hasattr(team, 'restrict_view'):
                        print(f"Restrict View: {team.restrict_view}")
                    
                    print("-" * 120)
                
                print(f"\nTotal teams displayed: {len(teams_to_display)}")
            
            print("=" * 120)
            
            enterprise.close()
            keeper_auth_context.close()
            
        except KeeperApiError as e:
            print(f"\nAPI Error: {e}")
            keeper_auth_context.close()
        except Exception as e:
            print(f"\nError loading enterprise data: {e}")
            keeper_auth_context.close()

