import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.vault import sqlite_storage, vault_online
from keepersdk.constants import KEEPER_PUBLIC_HOSTS


def login():
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
    username = config.get().last_login or input('Enter username: ')
    login_auth_context.resume_session = True
    login_auth_context.login(username)
    logged_in_with_persistent = True
    while not login_auth_context.login_step.is_final():
        if isinstance(login_auth_context.login_step, login_auth.LoginStepDeviceApproval):
            login_auth_context.login_step.send_push(login_auth.DeviceApprovalChannel.KeeperPush)
            print("Device approval request sent.")
            input()
        elif isinstance(login_auth_context.login_step, login_auth.LoginStepPassword):
            login_auth_context.login_step.verify_password(getpass.getpass('Enter password: '))
        elif isinstance(login_auth_context.login_step, login_auth.LoginStepTwoFactor):
            channel = login_auth_context.login_step.get_channels()[0]
            login_auth_context.login_step.send_code(channel.channel_uid, getpass.getpass(f'Enter 2FA code for {channel.channel_name}: '))
        else:
            raise NotImplementedError(f"Unsupported login step type: {type(login_auth_context.login_step).__name__}")
        logged_in_with_persistent = False
    if logged_in_with_persistent:
        print("Successfully logged in with persistent login")
    if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
        return login_auth_context.login_step.take_keeper_auth()
    return None


def list_teams(keeper_auth_context: keeper_auth.KeeperAuth):
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(lambda: conn, vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8'))
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    vault.sync_down()
    teams = list(vault.vault_data.teams())
    if not teams:
        print("\nNo teams found in vault")
    else:
        print(f"\nTeams in Vault ({len(teams)})\n{'=' * 120}")
        print(f"{'Team Name':<40} {'Team UID':<40} {'Records Shared':<20}\n{'-' * 120}")
        for team in teams:
            team_name = team.name if team.name else '(Unnamed)'
            #ToDo: shared_records_count
            shared_records_count = sum(1 for r in vault.vault_data.records() if hasattr(r, 'shared') and r.shared)
            print(f"{team_name[:39]:<40} {team.team_uid[:39]:<40} {shared_records_count:<20}")
        print(f"{'-' * 120}\nTotal teams: {len(teams)}")
    print("=" * 120)
    vault.close()
    keeper_auth_context.close()


def main():
    keeper_auth_context = login()
    if keeper_auth_context:
        list_teams(keeper_auth_context)
    else:
        print("Login failed.")


if __name__ == "__main__":
    main()
