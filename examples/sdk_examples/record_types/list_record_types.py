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


def list_record_types(keeper_auth_context: keeper_auth.KeeperAuth):
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(lambda: conn, vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8'))
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    vault.sync_down()
    print("\nAvailable Record Types\n" + "=" * 100)
    record_types_list = list(vault.vault_data.get_record_types())
    if not record_types_list:
        print("\nNo record types found")
    else:
        print(f"\nFound {len(record_types_list)} record type(s)\n{'-' * 100}")
        print(f"{'ID':<10} {'Name':<40} {'Scope':<15} {'Description':<30}\n{'-' * 100}")
        record_types_dict = {}
        for rt in record_types_list:
            rt_id = str(rt.id) if hasattr(rt, 'id') else 'N/A'
            rt_name = rt.name if hasattr(rt, 'name') else 'N/A'
            rt_scope = str(rt.scope) if hasattr(rt, 'scope') else 'N/A'
            rt_desc = (rt.description[:29] if rt.description else '') if hasattr(rt, 'description') else ''
            record_types_dict[rt_name.lower()] = rt
            print(f"{rt_id[:9]:<10} {rt_name[:39]:<40} {rt_scope[:14]:<15} {rt_desc:<30}")
        print("-" * 100)
        rt_name_to_view = input('\nEnter record type name to view details (or press Enter to skip): ').strip()
        if rt_name_to_view and rt_name_to_view.lower() in record_types_dict:
            rt = record_types_dict[rt_name_to_view.lower()]
            print(f"\nRecord Type Details: {rt.name if hasattr(rt, 'name') else rt_name_to_view}\n{'=' * 100}")
            if hasattr(rt, 'fields') and rt.fields:
                print(f"\nFields ({len(rt.fields)}):\n{'-' * 100}")
                print(f"{'Field Type':<25} {'Label':<30} {'Required':<10}\n{'-' * 100}")
                for field in rt.fields:
                    print(f"{(field.type if hasattr(field, 'type') else 'N/A')[:24]:<25} {(field.label if hasattr(field, 'label') else '')[:29]:<30} {'Yes' if (hasattr(field, 'required') and field.required) else 'No':<10}")
            print("=" * 100)
    print("\n" + "=" * 100)
    vault.close()
    keeper_auth_context.close()


def main():
    keeper_auth_context = login()
    if keeper_auth_context:
        list_record_types(keeper_auth_context)
    else:
        print("Login failed.")


if __name__ == "__main__":
    main()
