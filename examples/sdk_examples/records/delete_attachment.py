import getpass
import sqlite3

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_record, record_management
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


def delete_attachment(keeper_auth_context):
    """
    Delete an attachment from a record.
    
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

    print("Deleting attachment from record...")
    print("-" * 50)
    
    record_uid = input('Enter record UID (or leave empty to search): ').strip()
    
    if not record_uid:
        print('\nSearching for records with attachments...')
        for record_info in vault.vault_data.records():
            record = vault.vault_data.load_record(record_info.record_uid)
            has_attachments = False
            
            if hasattr(record, 'attachments') and record.attachments:
                has_attachments = True
            elif hasattr(record, 'file_ref') and record.file_ref:
                has_attachments = True
            
            if has_attachments:
                print(f'  - {record_info.title} ({record_info.record_uid})')
                record_uid = record_info.record_uid
                break
        
        if not record_uid:
            print('No records with attachments found')
    
    if record_uid:
        try:
            record = vault.vault_data.load_record(record_uid)
            
            if isinstance(record, vault_record.PasswordRecord):
                if record.attachments:
                    print(f'\nAttachments in record "{record.title}":')
                    for i, atta in enumerate(record.attachments, 1):
                        print(f'{i}. {atta.title or atta.name} (ID: {atta.id}, Size: {atta.size} bytes)')
                    
                    attachment_name = input('\nEnter attachment name or ID to delete: ').strip()
                    
                    if attachment_name:
                        attachment_found = False
                        for atta in record.attachments[:]:
                            if atta.id == attachment_name or atta.title == attachment_name or atta.name == attachment_name:
                                print(f'\nDeleting attachment: {atta.title or atta.name}')
                                record.attachments.remove(atta)
                                attachment_found = True
                                break
                        
                        if attachment_found:
                            record_management.update_record(vault, record)
                            
                            print("-" * 50)
                            print('Successfully deleted attachment!')
                            print("-" * 50)
                            
                            vault.sync_down()
                        else:
                            print(f'Attachment "{attachment_name}" not found')
                    else:
                        print('No attachment name provided')
                else:
                    print(f'Record "{record.title}" has no attachments')
                    
            elif isinstance(record, vault_record.TypedRecord):
                from keepersdk.vault.record_facades import FileRefRecordFacade
                
                facade = FileRefRecordFacade()
                facade.record = record
                
                if isinstance(facade.file_ref, list) and facade.file_ref:
                    print(f'\nFile references in record "{record.title}":')
                    for i, file_uid in enumerate(facade.file_ref, 1):
                        file_record = vault.vault_data.load_record(file_uid)
                        if isinstance(file_record, vault_record.FileRecord):
                            print(f'{i}. {file_record.title} (UID: {file_uid})')
                    
                    file_ref_input = input('\nEnter file UID to delete: ').strip()
                    
                    if file_ref_input in facade.file_ref:
                        print(f'\nDeleting file reference: {file_ref_input}')
                        facade.file_ref.remove(file_ref_input)
                        
                        record_management.update_record(vault, record)
                        
                        print("-" * 50)
                        print('Successfully deleted file reference!')
                        print("-" * 50)
                        
                        vault.sync_down()
                    else:
                        print(f'File reference "{file_ref_input}" not found')
                else:
                    print(f'Record "{record.title}" has no file references')
            else:
                print(f'Record type {type(record)} does not support attachments')
                
        except Exception as e:
            print(f'Error deleting attachment: {str(e)}')
            import traceback
            traceback.print_exc()
    
    vault.close()
    keeper_auth_context.close()


def main():
    """
    Main entry point for the delete attachment script.
    Performs login and deletes an attachment.
    """
    keeper_auth_context = login()
    
    if keeper_auth_context:
        delete_attachment(keeper_auth_context)
    else:
        print("Login failed. Unable to delete attachment.")


if __name__ == "__main__":
    main()
