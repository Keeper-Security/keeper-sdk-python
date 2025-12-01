import getpass
import logging

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk import utils

logging.getLogger('asyncio').setLevel(logging.CRITICAL)

config = configuration.JsonConfigurationStorage()
keeper_endpoint = endpoint.KeeperEndpoint(config)
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
        raise NotImplementedError()
    logged_in_with_persistent = False

if logged_in_with_persistent:
    print("Successfully logged in with persistent login")

if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
    keeper_auth_context = login_auth_context.login_step.take_keeper_auth()
    
    auth = keeper_auth_context.auth_context
    
    print("\n" + "=" * 60)
    print("WHO AM I - Current User Information")
    print("=" * 60)
    
    print(f"\nUsername: {auth.username}")
    print(f"Server: {keeper_endpoint.server}")
    
    if auth.account_uid:
        print(f"Account UID: {utils.base64_url_encode(auth.account_uid)}")
    
    print(f"\nEnterprise Admin: {'Yes' if auth.is_enterprise_admin else 'No'}")
    if auth.enterprise_id:
        print(f"Enterprise ID: {auth.enterprise_id}")
    
    if hasattr(auth, 'is_mc_superadmin') and auth.is_mc_superadmin:
        print(f"MC Superadmin: Yes")
    
    if auth.license:
        print(f"\nLicense Information:")
        for key, value in auth.license.items():
            if isinstance(value, (str, int, bool)):
                print(f"  {key}: {value}")
    
    if auth.settings:
        print(f"\nAccount Settings:")
        for key, value in auth.settings.items():
            if isinstance(value, (str, int, bool)):
                print(f"  {key}: {value}")
    
    if auth.sso_login_info:
        print(f"\nSSO Login: Enabled")
        print(f"  SSO Provider: {auth.sso_login_info.sso_provider_name if hasattr(auth.sso_login_info, 'sso_provider_name') else 'N/A'}")
    
    session_restriction = auth.session_token_restriction
    print(f"\nSession Status: {session_restriction.name if hasattr(session_restriction, 'name') else str(session_restriction)}")
    
    print("\n" + "=" * 60)
    
    keeper_auth_context.close()

