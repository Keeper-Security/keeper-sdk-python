import getpass
import sqlite3
from datetime import datetime

from keepersdk.authentication import login_auth, configuration, endpoint, keeper_auth
from keepersdk.vault import sqlite_storage, vault_online, ksm_management
from keepersdk.constants import KEEPER_PUBLIC_HOSTS
from keepersdk import utils


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


def list_one_time_shares(keeper_auth_context: keeper_auth.KeeperAuth):
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(lambda: conn, vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8'))
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    vault.sync_down()
    try:
        record_search = input('Enter record name/UID to check for shares (or leave empty for all records): ').strip()
        record_uids = []
        for record_info in vault.vault_data.records():
            if record_info.version not in (2, 3):
                continue
            if not record_search or record_search.lower() in record_info.title.lower() or record_search == record_info.record_uid:
                record_uids.append(record_info.record_uid)
        if not record_uids:
            print("\nNo records found to check for one-time shares")
        else:
            app_infos = ksm_management.get_app_info(vault=vault, app_uid=record_uids[:100])
            shares_found = []
            now = utils.current_milli_time()
            for app_info in app_infos:
                if not app_info.isExternalShare:
                    continue
                record_uid = utils.base64_url_encode(app_info.appRecordUid)
                record_info = vault.vault_data.get_record(record_uid)
                record_title = record_info.title if record_info else 'Unknown'
                for client in app_info.clients:
                    shares_found.append({
                        'record_title': record_title,
                        'share_name': client.id if client.id else 'Unnamed',
                        'created': datetime.fromtimestamp(client.createdOn / 1000) if client.createdOn else None,
                        'expires': datetime.fromtimestamp(client.accessExpireOn / 1000) if client.accessExpireOn else None,
                        'expired': now > client.accessExpireOn if client.accessExpireOn else False,
                        'opened': datetime.fromtimestamp(client.firstAccess / 1000) if client.firstAccess else None
                    })
            if not shares_found:
                print("\nNo one-time shares found")
            else:
                print(f"\nOne-Time Shares ({len(shares_found)})\n{'=' * 130}")
                print(f"{'Record Title':<30} {'Share Name':<20} {'Created':<20} {'Expires':<20} {'Status':<15}\n{'-' * 130}")
                for share in shares_found:
                    status = 'Expired' if share['expired'] else ('Opened' if share['opened'] else 'Active')
                    created = share['created'].strftime('%Y-%m-%d %H:%M') if share['created'] else 'N/A'
                    expires = share['expires'].strftime('%Y-%m-%d %H:%M') if share['expires'] else 'N/A'
                    print(f"{share['record_title'][:29]:<30} {share['share_name'][:19]:<20} {created:<20} {expires:<20} {status:<15}")
                print(f"{'-' * 130}\nTotal: {len(shares_found)}")
        print("=" * 130)
    except Exception as e:
        print(f"Error retrieving one-time shares: {e}")
    vault.close()
    keeper_auth_context.close()


def main():
    keeper_auth_context = login()
    if keeper_auth_context:
        list_one_time_shares(keeper_auth_context)
    else:
        print("Login failed.")


if __name__ == "__main__":
    main()
