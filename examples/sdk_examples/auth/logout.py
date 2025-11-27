import getpass

from keepersdk.authentication import login_auth, configuration, endpoint

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
    
    print(f"\nLogged in as: {keeper_auth_context.auth_context.username}")
    
    confirm = input("\nDo you want to logout? (yes/no): ").strip().lower()
    
    if confirm == 'yes':
        keeper_auth_context.close()
        print("\n" + "=" * 50)
        print("LOGOUT SUCCESSFUL")
        print("=" * 50)
        print("Session has been closed.")
        print("=" * 50)
    else:
        print("Logout cancelled. Session still active.")
        keeper_auth_context.close()

