import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_record
from keepersdk.constants import KEEPER_PUBLIC_HOSTS


def login():
    """
    Handle the login process including server selection, authentication,
    and multi-factor authentication steps.
    
    Returns:
        keeper_auth_context: The authenticated Keeper context, or None if login fails.
    """
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
            raise NotImplementedError(f"Unsupported login step type: {type(login_auth_context.login_step).__name__}")
        logged_in_with_persistent = False
    
    if logged_in_with_persistent:
        print("Successfully logged in with persistent login")
    
    if isinstance(login_auth_context.login_step, login_auth.LoginStepConnected):
        return login_auth_context.login_step.take_keeper_auth()
    
    return None


def generate_file_report(keeper_auth_context):
    """
    Generate a report of all file attachments in the vault.
    
    Args:
        keeper_auth_context: The authenticated Keeper context.
    """
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8')
    )
    
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    vault.sync_down()

    print("File Attachment Report")
    print("=" * 50)
    
    total_records = 0
    records_with_files = 0
    total_files = 0
    total_size = 0
    
    file_details = []
    
    for record_info in vault.vault_data.records():
        total_records += 1
        
        try:
            record = vault.vault_data.load_record(record_info.record_uid)
            record_has_files = False
            record_file_count = 0
            record_file_size = 0
            
            if isinstance(record, vault_record.PasswordRecord):
                if record.attachments:
                    record_has_files = True
                    record_file_count = len(record.attachments)
                    
                    for atta in record.attachments:
                        file_size = atta.size if hasattr(atta, 'size') and atta.size else 0
                        file_name = atta.title or atta.name
                        file_details.append({
                            'record_title': record.title,
                            'record_uid': record_info.record_uid,
                            'file_name': file_name,
                            'file_id': atta.id,
                            'file_size': file_size
                        })
                        record_file_size += file_size
            
            elif isinstance(record, vault_record.TypedRecord):
                from keepersdk.vault.record_facades import FileRefRecordFacade
                facade = FileRefRecordFacade()
                facade.record = record
                
                if isinstance(facade.file_ref, list) and facade.file_ref:
                    record_has_files = True
                    record_file_count = len(facade.file_ref)
                    
                    for file_uid in facade.file_ref:
                        file_record = vault.vault_data.load_record(file_uid)
                        if isinstance(file_record, vault_record.FileRecord):
                            file_size = file_record.size if hasattr(file_record, 'size') and file_record.size else 0
                            file_details.append({
                                'record_title': record.title,
                                'record_uid': record_info.record_uid,
                                'file_name': file_record.title,
                                'file_id': file_uid,
                                'file_size': file_size
                            })
                            record_file_size += file_size
            
            if record_has_files:
                records_with_files += 1
                total_files += record_file_count
                total_size += record_file_size
                
        except Exception as e:
            print(f"Warning: Error processing record {record_info.record_uid}: {str(e)}")
            continue
    
    def format_size(size_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    print("\nSummary:")
    print("-" * 50)
    print(f"Total records in vault: {total_records}")
    print(f"Records with attachments: {records_with_files}")
    print(f"Total attachments: {total_files}")
    print(f"Total storage used: {format_size(total_size)}")
    
    if file_details:
        print("\n" + "=" * 50)
        print("Detailed File List:")
        print("=" * 50)
        
        file_details.sort(key=lambda x: x['file_size'], reverse=True)
        
        for i, file_info in enumerate(file_details, 1):
            print(f"\n{i}. {file_info['file_name']}")
            print(f"   Record: {file_info['record_title']}")
            print(f"   Record UID: {file_info['record_uid']}")
            print(f"   File Size: {format_size(file_info['file_size'])}")
            print(f"   File ID: {file_info['file_id']}")
            
            if i >= 20 and len(file_details) > 20:
                remaining = len(file_details) - 20
                print(f"\n... and {remaining} more file(s)")
                break
    else:
        print("\nNo file attachments found in vault.")
    
    print("\n" + "=" * 50)
    
    vault.close()
    keeper_auth_context.close()


def main():
    """
    Main entry point for the file report script.
    Performs login and generates file attachment report.
    """
    keeper_auth_context = login()
    
    if keeper_auth_context:
        generate_file_report(keeper_auth_context)
    else:
        print("Login failed. Unable to generate file report.")


if __name__ == "__main__":
    main()
