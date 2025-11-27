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
            
            alert_id_or_name = input('Enter alert ID or name: ').strip()
            
            if not alert_id_or_name:
                print("Alert identifier cannot be empty")
            else:
                alert_found = None
                alert_id_num = int(alert_id_or_name) if alert_id_or_name.isnumeric() else 0
                
                for alert in alert_filters:
                    if alert_id_num > 0 and alert.get('id') == alert_id_num:
                        alert_found = alert
                        break
                    elif alert.get('name', '').lower() == alert_id_or_name.lower():
                        alert_found = alert
                        break
                
                if not alert_found:
                    print(f"Alert '{alert_id_or_name}' not found")
                else:
                    print("\nAudit Alert Details")
                    print("=" * 100)
                    print(f"ID: {alert_found.get('id', 'N/A')}")
                    print(f"Name: {alert_found.get('name', 'N/A')}")
                    print(f"Active: {'Yes' if alert_found.get('active', False) else 'No'}")
                    
                    frequency_data = alert_found.get('frequency', {})
                    if isinstance(frequency_data, dict):
                        period = frequency_data.get('period', 'event')
                        count = frequency_data.get('count', '')
                        print(f"Frequency: {count} {period}" if count else f"Frequency: {period}")
                    
                    alert_filter = alert_found.get('filter', {})
                    if alert_filter:
                        print("\nFilters:")
                        for key, value in alert_filter.items():
                            print(f"  {key}: {value}")
                    
                    context_entry = next((x for x in alert_context if x.get('id') == alert_found.get('id')), None)
                    if context_entry:
                        recipients = context_entry.get('recipients', [])
                        if recipients and isinstance(recipients, list):
                            print(f"\nRecipients ({len(recipients)}):")
                            for recipient in recipients:
                                print(f"  - {recipient}")
                        
                        triggers = context_entry.get('triggers', [])
                        if triggers and isinstance(triggers, list):
                            print(f"\nTriggers ({len(triggers)}):")
                            for trigger in triggers[:5]:
                                timestamp = trigger.get('timestamp', 'N/A')
                                print(f"  - {timestamp}")
                            if len(triggers) > 5:
                                print(f"  ... and {len(triggers) - 5} more")
                    
                    print("=" * 100)
            
            keeper_auth_context.close()
            
        except KeeperApiError as e:
            print(f"\nAPI Error: {e}")
            keeper_auth_context.close()
        except Exception as e:
            print(f"\nError loading audit alert: {e}")
            keeper_auth_context.close()

