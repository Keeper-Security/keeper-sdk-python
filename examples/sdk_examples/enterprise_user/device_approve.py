import getpass
import sqlite3
import time

from keepersdk.authentication import login_auth, configuration, endpoint
from keepersdk.enterprise import enterprise_loader, sqlite_enterprise_storage
from keepersdk.proto import enterprise_pb2, APIRequest_pb2
from keepersdk import utils, crypto
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
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


def approve_devices(keeper_auth_context):
    """
    Manage device approval requests for enterprise users.
    
    Args:
        keeper_auth_context: The authenticated Keeper context with enterprise admin privileges.
    """
    if not keeper_auth_context.auth_context.is_enterprise_admin:
        print("Error: You must be an enterprise admin to approve devices")
        keeper_auth_context.close()
        return
    
    try:
        enterprise_id = keeper_auth_context.auth_context.enterprise_id or 0
        conn = sqlite3.Connection('file::memory:', uri=True)
        enterprise_storage = sqlite_enterprise_storage.SqliteEnterpriseStorage(
            lambda: conn,
            enterprise_id
        )
        
        loader = enterprise_loader.EnterpriseLoader(keeper_auth_context, enterprise_storage)
        loader.load()
        
        enterprise_data = loader.enterprise_data
        
        approval_requests = list(enterprise_data.device_approval_requests.get_all_entities())
        
        if not approval_requests:
            print("\nNo pending device approval requests")
        else:
            print("\n" + "=" * 80)
            print("PENDING DEVICE APPROVAL REQUESTS")
            print("=" * 80)
            
            user_lookup = {u.enterprise_user_id: u.username 
                          for u in enterprise_data.users.get_all_entities()}
            
            for i, req in enumerate(approval_requests, 1):
                username_display = user_lookup.get(req.enterprise_user_id, 'Unknown')
                date_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(req.date / 1000))
                device_id_short = req.encrypted_device_token[:16] if req.encrypted_device_token else 'N/A'
                
                print(f"\n{i}. Request Details:")
                print(f"   User: {username_display}")
                print(f"   User ID: {req.enterprise_user_id}")
                print(f"   Device Name: {req.device_name}")
                print(f"   Device Type: {req.device_type}")
                print(f"   Client Version: {req.client_version}")
                print(f"   IP Address: {req.ip_address}")
                print(f"   Location: {req.location}")
                print(f"   Date: {date_str}")
                print(f"   Device ID: {device_id_short}...")
            
            print("\n" + "-" * 80)
            print("\nOptions:")
            print("  1. Approve all pending devices")
            print("  2. Deny all pending devices")
            print("  3. Approve specific device (by number)")
            print("  4. Deny specific device (by number)")
            print("  5. Exit without action")
            
            choice = input("\nEnter choice (1-5): ").strip()
            
            if choice in ['1', '2', '3', '4']:
                approve_rq = enterprise_pb2.ApproveUserDevicesRequest()
                devices_to_process = []
                is_deny = choice in ['2', '4']
                
                if choice in ['1', '2']:
                    devices_to_process = approval_requests
                elif choice in ['3', '4']:
                    try:
                        num = int(input("Enter device number: ").strip())
                        if 1 <= num <= len(approval_requests):
                            devices_to_process = [approval_requests[num - 1]]
                        else:
                            print("Invalid device number")
                    except ValueError:
                        print("Invalid input")
                
                if devices_to_process:
                    for req in devices_to_process:
                        device_rq = enterprise_pb2.ApproveUserDeviceRequest()
                        device_rq.enterpriseUserId = req.enterprise_user_id
                        device_rq.encryptedDeviceToken = utils.base64_url_decode(req.encrypted_device_token)
                        device_rq.denyApproval = is_deny
                        
                        if not is_deny and req.device_public_key:
                            try:
                                curve = ec.SECP256R1()
                                data_key_rq = APIRequest_pb2.UserDataKeyRequest()
                                data_key_rq.enterpriseUserId.append(req.enterprise_user_id)
                                
                                data_key_rs = keeper_auth_context.execute_auth_rest(
                                    'enterprise/get_enterprise_user_data_key',
                                    data_key_rq,
                                    response_type=APIRequest_pb2.EnterpriseUserIdDataKeyPair
                                )
                                
                                if data_key_rs and data_key_rs.encryptedDataKey:
                                    keys = enterprise_data.enterprise_info.keys
                                    if keys and keys.ecc_encrypted_private_key:
                                        ecc_priv_data = utils.base64_url_decode(keys.ecc_encrypted_private_key)
                                        ecc_priv_data = crypto.decrypt_aes_v2(
                                            ecc_priv_data, 
                                            enterprise_data.enterprise_info.tree_key
                                        )
                                        private_value = int.from_bytes(ecc_priv_data, byteorder='big', signed=False)
                                        ecc_private_key = ec.derive_private_key(private_value, curve, default_backend())
                                        
                                        enc_data_key = data_key_rs.encryptedDataKey
                                        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                                            curve, enc_data_key[:65])
                                        shared_key = ecc_private_key.exchange(ec.ECDH(), ephemeral_public_key)
                                        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                                        digest.update(shared_key)
                                        enc_key = digest.finalize()
                                        data_key = crypto.decrypt_aes_v2(enc_data_key[65:], enc_key)
                                        
                                        ephemeral_key = ec.generate_private_key(curve, default_backend())
                                        device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                                            curve, utils.base64_url_decode(req.device_public_key))
                                        shared_device_key = ephemeral_key.exchange(ec.ECDH(), device_public_key)
                                        digest2 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                                        digest2.update(shared_device_key)
                                        enc_device_key = digest2.finalize()
                                        encrypted_data_key = crypto.encrypt_aes_v2(data_key, enc_device_key)
                                        ephemeral_public = ephemeral_key.public_key().public_bytes(
                                            serialization.Encoding.X962, 
                                            serialization.PublicFormat.UncompressedPoint
                                        )
                                        device_rq.encryptedDeviceDataKey = ephemeral_public + encrypted_data_key
                            except Exception as e:
                                print(f"Warning: Could not encrypt data key for device: {e}")
                                continue
                        
                        approve_rq.deviceRequests.append(device_rq)
                    
                    if approve_rq.deviceRequests:
                        action = "Denying" if is_deny else "Approving"
                        print(f"\n{action} {len(approve_rq.deviceRequests)} device(s)...")
                        
                        try:
                            keeper_auth_context.execute_auth_rest(
                                'enterprise/approve_user_devices',
                                approve_rq,
                                response_type=enterprise_pb2.ApproveUserDevicesResponse
                            )
                            
                            action_done = "denied" if is_deny else "approved"
                            print(f"\nSuccessfully {action_done} {len(approve_rq.deviceRequests)} device(s)")
                            
                        except Exception as e:
                            print(f"\nError processing devices: {e}")
                    else:
                        print("\nNo devices to process")
            else:
                print("Exiting without action")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        keeper_auth_context.close()


def main():
    """
    Main entry point for the device approval script.
    Performs login and manages device approval requests.
    """
    keeper_auth_context = login()
    
    if keeper_auth_context:
        approve_devices(keeper_auth_context)
    else:
        print("Login failed. Unable to manage device approvals.")


if __name__ == "__main__":
    main()
