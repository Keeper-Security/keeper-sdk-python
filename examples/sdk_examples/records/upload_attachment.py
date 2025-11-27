import getpass
import sqlite3
import os

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.vault import sqlite_storage, vault_online, vault_record, attachment, record_management

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
    
    conn = sqlite3.Connection('file::memory:', uri=True)
    vault_storage = sqlite_storage.SqliteVaultStorage(
        lambda: conn,
        vault_owner=bytes(keeper_auth_context.auth_context.username, 'utf-8')
    )
    
    vault = vault_online.VaultOnline(keeper_auth_context, vault_storage)
    vault.sync_down()

    print("Uploading attachment to record...")
    print("-" * 50)
    
    record_uid = input('Enter record UID (or leave empty to use first record): ').strip()
    
    if not record_uid:
        for record_info in vault.vault_data.records():
            record_uid = record_info.record_uid
            print(f'Using record: {record_info.title} ({record_uid})')
            break
    
    if record_uid:
        file_path = input('Enter file path to upload: ').strip()
        
        if not file_path:
            print('No file path provided. Example: /path/to/file.txt')
        elif not os.path.isfile(file_path):
            print(f'File not found: {file_path}')
        else:
            try:
                record = vault.vault_data.load_record(record_uid)
                
                if not isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
                    print(f'Record type {type(record)} does not support attachments')
                else:
                    print(f'Uploading file: {os.path.basename(file_path)}')
                    print(f'File size: {os.path.getsize(file_path)} bytes')
                    
                    upload_task = attachment.FileUploadTask(file_path)
                    
                    attachment.upload_attachments(vault, record, [upload_task])
                    
                    record_management.update_record(vault, record)
                    
                    print("-" * 50)
                    print('Successfully uploaded attachment!')
                    print(f'File: {os.path.basename(file_path)}')
                    print(f'Record: {record.title}')
                    print("-" * 50)
                    
                    vault.sync_down()
                    
            except Exception as e:
                print(f'Error uploading attachment: {str(e)}')
                import traceback
                traceback.print_exc()
    else:
        print('No records found in vault')
    
    vault.close()
    keeper_auth_context.close()
