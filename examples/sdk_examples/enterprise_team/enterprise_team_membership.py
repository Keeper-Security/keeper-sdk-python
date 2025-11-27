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
            
            team_search = input('Enter team name or UID: ').strip()
            
            if not team_search:
                print('No team specified')
            else:
                team_found = None
                
                for team in enterprise.enterprise_data.teams.get_all():
                    team_name = team.name if hasattr(team, 'name') and team.name else ''
                    team_uid = team.team_uid if hasattr(team, 'team_uid') else ''
                    
                    if (team_search.lower() in team_name.lower() or 
                        team_search == team_uid):
                        team_found = team
                        break
                
                if team_found:
                    team_name = team_found.name if hasattr(team_found, 'name') and team_found.name else 'N/A'
                    team_uid = team_found.team_uid if hasattr(team_found, 'team_uid') else 'N/A'
                    
                    print(f"\nTeam Membership for: {team_name}")
                    print(f"Team UID: {team_uid}")
                    print("=" * 100)
                    
                    team_users = list(enterprise.enterprise_data.team_users.get_links_by_subject(team_uid))
                    
                    if team_users:
                        print(f"\nUsers ({len(team_users)}):")
                        print("-" * 100)
                        print(f"{'Username':<40} {'Email':<40} {'Status':<20}")
                        print("-" * 100)
                        
                        for team_user in team_users:
                            user = enterprise.enterprise_data.users.get_entity(team_user.user_id)
                            if user:
                                user_name = user.display_name if hasattr(user, 'display_name') and user.display_name else user.username
                                user_email = user.username
                                user_status = user.status.name if hasattr(user, 'status') else 'unknown'
                                print(f"{user_name[:39]:<40} {user_email[:39]:<40} {user_status:<20}")
                    else:
                        print("\nNo users in this team")
                    
                    queued_users = list(enterprise.enterprise_data.queued_team_users.get_links_by_subject(team_uid))
                    if queued_users:
                        print(f"\nQueued Users ({len(queued_users)}):")
                        print("-" * 100)
                        for queued_user in queued_users:
                            user = enterprise.enterprise_data.users.get_entity(queued_user.user_id)
                            if user:
                                print(f"  - {user.username}")
                    
                    print("=" * 100)
                else:
                    print(f'\nNo team found matching: "{team_search}"')
            
            enterprise.close()
            keeper_auth_context.close()
            
        except KeeperApiError as e:
            print(f"\nAPI Error: {e}")
            keeper_auth_context.close()
        except Exception as e:
            print(f"\nError loading enterprise data: {e}")
            keeper_auth_context.close()

