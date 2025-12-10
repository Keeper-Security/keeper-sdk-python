import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.vault import sqlite_storage, vault_online, vault_record
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


def copy_field(keeper_auth_context: keeper_auth.KeeperAuth):
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(lambda: conn, vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8'))
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    vault.sync_down()
    record_search = input('Enter record title or UID: ').strip()
    if not record_search:
        print("Record identifier cannot be empty")
    else:
        record_found = None
        for record_info in vault.vault_data.records():
            if record_search.lower() in record_info.title.lower() or record_search == record_info.record_uid:
                record_found = record_info
                break
        if not record_found:
            print(f"Record '{record_search}' not found")
        else:
            record = vault.vault_data.load_record(record_found.record_uid)
            print(f"\nRecord: {record_found.title}\n1. Password\n2. Login/Username\n3. URL\n4. TOTP Code\n5. Record UID")
            choice = input("\nEnter choice (1-5): ").strip()
            output_value, output_label = None, None
            if choice == '1':
                if isinstance(record, vault_record.PasswordRecord):
                    output_value, output_label = record.password, "Password"
                elif isinstance(record, vault_record.TypedRecord):
                    for field in record.fields:
                        if field.field_type == 'password' and field.value:
                            output_value, output_label = (field.value[0] if isinstance(field.value, list) else field.value), "Password"
                            break
            elif choice == '2':
                if isinstance(record, vault_record.PasswordRecord):
                    output_value, output_label = record.login, "Login"
                elif isinstance(record, vault_record.TypedRecord):
                    for field in record.fields:
                        if field.field_type == 'login' and field.value:
                            output_value, output_label = (field.value[0] if isinstance(field.value, list) else field.value), "Login"
                            break
            elif choice == '3':
                if isinstance(record, vault_record.PasswordRecord):
                    output_value, output_label = record.link, "URL"
                elif isinstance(record, vault_record.TypedRecord):
                    for field in record.fields:
                        if field.field_type == 'url' and field.value:
                            output_value, output_label = (field.value[0] if isinstance(field.value, list) else field.value), "URL"
                            break
            elif choice == '4':
                totp_url = None
                if isinstance(record, vault_record.PasswordRecord) and hasattr(record, 'totp') and record.totp:
                    totp_url = record.totp
                elif isinstance(record, vault_record.TypedRecord):
                    for field in record.fields:
                        if field.field_type == 'oneTimeCode' and field.value:
                            totp_url = field.value[0] if isinstance(field.value, list) else field.value
                            break
                if totp_url:
                    print(f"TOTP URL: {totp_url}")
                    #pending for totp
            elif choice == '5':
                output_value, output_label = record_found.record_uid, "Record UID"
            if output_value and output_label:
                print(f"\n{output_label}:\n{'=' * 80}\n{output_value}\n{'=' * 80}")
    vault.close()
    keeper_auth_context.close()


def main():
    keeper_auth_context = login()
    if keeper_auth_context:
        copy_field(keeper_auth_context)
    else:
        print("Login failed.")


if __name__ == "__main__":
    main()
