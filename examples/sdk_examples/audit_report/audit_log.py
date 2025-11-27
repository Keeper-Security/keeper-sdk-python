import getpass

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.enterprise import audit_report
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
            report = audit_report.RawAuditReport(keeper_auth_context)
            
            limit_input = input('Enter number of events to retrieve (default 50, -1 for all): ').strip()
            if limit_input:
                report.limit = int(limit_input)
            else:
                report.limit = 50
            
            use_filter = input('Apply filters? (y/n): ').strip().lower() == 'y'
            
            if use_filter:
                filter_obj = audit_report.AuditReportFilter()
                
                time_range = input('Time range (today/yesterday/last_7_days/last_30_days or press Enter to skip): ').strip()
                if time_range:
                    filter_obj.created = time_range
                
                event_type = input('Event type (e.g., login, or press Enter to skip): ').strip()
                if event_type:
                    filter_obj.event_type = event_type
                
                username_filter = input('Username filter (or press Enter to skip): ').strip()
                if username_filter:
                    filter_obj.username = username_filter
                
                report.filter = filter_obj
            
            print("\nFetching audit log events...")
            print("=" * 120)
            
            event_count = 0
            for event in report.execute_audit_report():
                event_count += 1
                
                created = event.get('created', 'N/A')
                username = event.get('username', 'N/A')
                audit_event_type = event.get('audit_event_type', 'N/A')
                ip_address = event.get('ip_address', 'N/A')
                keeper_version = event.get('keeper_version', 'N/A')
                
                print(f"\nEvent #{event_count}")
                print(f"  Timestamp: {created}")
                print(f"  User: {username}")
                print(f"  Event Type: {audit_event_type}")
                print(f"  IP Address: {ip_address}")
                print(f"  Keeper Version: {keeper_version}")
                
                if event_count >= 10 and report.limit > 10:
                    more = input(f"\nShowing {event_count} of {report.limit if report.limit > 0 else 'all'} events. Continue? (y/n): ").strip().lower()
                    if more != 'y':
                        break
            
            print("\n" + "=" * 120)
            print(f"Total events displayed: {event_count}")
            
            keeper_auth_context.close()
            
        except KeeperApiError as e:
            print(f"\nAPI Error: {e}")
            keeper_auth_context.close()
        except Exception as e:
            print(f"\nError retrieving audit log: {e}")
            keeper_auth_context.close()

