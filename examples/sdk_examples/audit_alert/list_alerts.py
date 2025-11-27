import getpass

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.errors import KeeperApiError

config = configuration.JsonConfigurationStorage()
keeper_endpoint = endpoint.KeeperEndpoint(config)
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
            rq = {
                'command': 'get_enterprise_setting',
                'include': ['AuditAlertContext', 'AuditAlertFilter']
            }
            settings = keeper_auth_context.execute_auth_command(rq)
            
            alert_filters = settings.get('AuditAlertFilter', [])
            alert_context = settings.get('AuditAlertContext', [])
            
            if not alert_filters:
                print("\nNo audit alerts configured")
            else:
                print("\nAudit Alerts")
                print("=" * 120)
                print(f"{'ID':<8} {'Name':<30} {'Frequency':<20} {'Active':<10} {'Recipients':<20}")
                print("-" * 120)
                
                for alert in alert_filters:
                    alert_id = alert.get('id', 'N/A')
                    alert_name = alert.get('name', 'N/A')
                    
                    frequency_data = alert.get('frequency', {})
                    if isinstance(frequency_data, dict):
                        period = frequency_data.get('period', 'event')
                        count = frequency_data.get('count', '')
                        frequency = f"{count} {period}" if count else period
                    else:
                        frequency = 'event'
                    
                    active = 'Yes' if alert.get('active', False) else 'No'
                    
                    context_entry = next((x for x in alert_context if x.get('id') == alert_id), None)
                    recipients_count = 0
                    if context_entry:
                        recipients = context_entry.get('recipients', [])
                        recipients_count = len(recipients) if isinstance(recipients, list) else 0
                    
                    print(f"{str(alert_id):<8} {alert_name[:29]:<30} {frequency[:19]:<20} {active:<10} {recipients_count:<20}")
                
                print("-" * 120)
                print(f"Total alerts: {len(alert_filters)}")
                print("=" * 120)
            
            keeper_auth_context.close()
            
        except KeeperApiError as e:
            print(f"\nAPI Error: {e}")
            keeper_auth_context.close()
        except Exception as e:
            print(f"\nError loading audit alerts: {e}")
            keeper_auth_context.close()

