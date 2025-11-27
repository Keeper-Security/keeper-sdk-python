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
            report = audit_report.SummaryAuditReport(keeper_auth_context)
            
            print("Available summary types: hour, day, week, month, span")
            summary_type = input('Enter summary type (default: day): ').strip() or 'day'
            report.summary_type = summary_type
            
            limit_input = input('Enter number of summary rows (default 100, max 2000): ').strip()
            if limit_input:
                report.limit = int(limit_input)
            else:
                report.limit = 100
            
            use_filter = input('Apply filters? (y/n): ').strip().lower() == 'y'
            
            if use_filter:
                filter_obj = audit_report.AuditReportFilter()
                
                time_range = input('Time range (today/yesterday/last_7_days/last_30_days or press Enter to skip): ').strip()
                if time_range:
                    filter_obj.created = time_range
                
                event_type = input('Event type (e.g., login, or press Enter to skip): ').strip()
                if event_type:
                    filter_obj.event_type = event_type
                
                report.filter = filter_obj
            
            add_aggregates = input('Add aggregates? (y/n): ').strip().lower() == 'y'
            if add_aggregates:
                report.aggregates = ['occurrences', 'first_created', 'last_created']
            
            add_columns = input('Add grouping columns? (y/n): ').strip().lower() == 'y'
            if add_columns:
                columns_input = input('Enter columns (comma-separated, e.g., audit_event_type,username): ').strip()
                if columns_input:
                    report.columns = [col.strip() for col in columns_input.split(',')]
            
            print(f"\nFetching {summary_type} summary report...")
            print("=" * 120)
            
            row_count = 0
            for row in report.execute_summary_report():
                row_count += 1
                
                print(f"\nRow #{row_count}")
                for key, value in row.items():
                    print(f"  {key}: {value}")
            
            print("\n" + "=" * 120)
            print(f"Total summary rows: {row_count}")
            
            keeper_auth_context.close()
            
        except KeeperApiError as e:
            print(f"\nAPI Error: {e}")
            keeper_auth_context.close()
        except Exception as e:
            print(f"\nError generating summary report: {e}")
            keeper_auth_context.close()

