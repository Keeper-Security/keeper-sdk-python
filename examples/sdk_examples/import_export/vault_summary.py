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


def show_vault_summary(keeper_auth_context: keeper_auth.KeeperAuth):
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(lambda: conn, vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8'))
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    vault.sync_down()
    print("\nVault Summary")
    print("=" * 100)
    total_records, v2_records, v3_records = 0, 0, 0
    for record_info in vault.vault_data.records():
        total_records += 1
        if record_info.version == 2:
            v2_records += 1
        elif record_info.version == 3:
            v3_records += 1
    total_folders = len(list(vault.vault_data.folders()))
    user_folders = sum(1 for f in vault.vault_data.folders() if f.folder_type == 'user_folder')
    shared_folders = vault.vault_data.shared_folder_count
    total_teams = len(list(vault.vault_data.teams()))
    print(f"\nRecords: Total={total_records}, V2(Legacy)={v2_records}, V3+(Modern)={v3_records}")
    print(f"Folders: Total={total_folders}, User={user_folders}, Shared={shared_folders}")
    print(f"Teams: {total_teams}")
    print("=" * 100)
    vault.close()
    keeper_auth_context.close()


def main():
    keeper_auth_context = login()
    if keeper_auth_context:
        show_vault_summary(keeper_auth_context)
    else:
        print("Login failed.")


if __name__ == "__main__":
    main()
