import json
from typing import Iterable, Union, Dict, Tuple, List

from keepersdk import crypto, utils
from login import configuration, endpoint, auth
from proto import AccountSummary_pb2, APIRequest_pb2
from vault import record_facades, vault_record, vault_types, vault_extensions


def get_configuration_storage():
    config = configuration.KeeperConfiguration()
    config.set_last_server(DefaultEnvironment)
    config.set_last_login(UserName)
    sc = configuration.ServerConfiguration(DefaultEnvironment)
    sc.server_key_id = 2
    config.servers().put(sc)
    device_token = utils.base64_url_encode(DeviceId)
    dc = configuration.DeviceConfiguration(device_token)
    dc.private_key = utils.base64_url_encode(crypto.unload_ec_private_key(DevicePrivateKey))
    dc.public_key = utils.base64_url_encode(crypto.unload_ec_public_key(DevicePublicKey))
    dsc = configuration.DeviceServerConfiguration(DefaultEnvironment)
    dsc.clone_code = utils.base64_url_encode(DeviceCloneCode)
    dc.get_server_info().put(dsc)
    config.devices().put(dc)
    uc = configuration.UserConfiguration(UserName)
    uc.last_device = configuration.UserDeviceConfiguration(device_token)
    config.users().put(uc)
    return configuration.InMemoryConfigurationStorage(config)


def generate_account_summary(keeper_endpoint):
    # type: (endpoint.KeeperEndpoint) -> AccountSummary_pb2.AccountSummaryElements
    result = AccountSummary_pb2.AccountSummaryElements()
    result.clientKey = crypto.encrypt_aes_v1(UserClientKey, UserDataKey)
    result.isEnterpriseAdmin = False
    result.keysInfo.encryptionParams = \
        utils.create_encryption_params(UserPassword, UserSalt, UserIterations, UserDataKey)
    pk = crypto.unload_rsa_private_key(UserRsaPrivateKey)
    result.keysInfo.encryptedPrivateKey = crypto.encrypt_aes_v1(pk, UserDataKey)
    pk = crypto.unload_ec_private_key(UserEcPrivateKey)
    result.keysInfo.encryptedEccPrivateKey = crypto.encrypt_aes_v2(pk, UserDataKey)
    result.keysInfo.eccPublicKey = crypto.unload_ec_public_key(UserEcPublicKey)
    config = keeper_endpoint.get_configuration_storage().get()
    for dc in config.devices().list():
        di = AccountSummary_pb2.DeviceInfo()
        di.clientVersion = TestClientVersion
        di.deviceName = 'Test Device'
        di.deviceStatus = APIRequest_pb2.DEVICE_OK
        di.encryptedDeviceToken = utils.base64_url_decode(dc.get_device_token())
        di.devicePublicKey = utils.base64_url_decode(dc.get_public_key())
    return result


def sync_down_response():  # type: () -> dict
    keys = {}    # type: Dict[str, bytes]
    teams = []
    shared_folders = []
    records = []
    meta_data = []

    for_sf = []
    for record in get_test_records():
        d, k = generate_record(record)
        keys[record.record_uid] = k
        has_shared_folder = len(records) in {2, 3}
        has_direct_share = len(records) == 3

        if has_shared_folder:
            d['shared'] = True
            for_sf.append(record.record_uid)
        if not has_shared_folder or has_direct_share:
            d['shared'] = has_direct_share
            md = {
                'record_uid': record.record_uid,
                'owner': not has_direct_share,
                'can_share': not has_direct_share,
                'can_edit': not has_direct_share,
            }
            if has_direct_share:
                md['record_key'] = utils.base64_url_encode(crypto.encrypt_rsa(k, UserRsaPublicKey))
                md['record_key_type'] = 2
            elif isinstance(record, vault_record.PasswordRecord):
                md['record_key'] = utils.base64_url_encode(crypto.encrypt_aes_v1(k, UserDataKey))
                md['record_key_type'] = 1
            else:
                md['record_key'] = utils.base64_url_encode(crypto.encrypt_aes_v2(k, UserDataKey))
                md['record_key_type'] = 3
            meta_data.append(md)
        records.append(d)

    record_keys = []
    for_team = []
    for shared_folder in get_test_shared_folders():
        record_keys.clear()
        if len(shared_folders) == 0:
            record_keys.extend(((x, keys[x]) for x in for_sf))
        else:
            record_uid = for_sf[-1]
            record_keys.append((record_uid, keys[record_uid]))
        use_key = len(shared_folders) == 0
        d, k = generate_shared_folder(shared_folder, use_key, record_keys)
        if not use_key:
            for_team.append(d)
        keys[shared_folder.shared_folder_uid] = k
        shared_folders.append(d)

    for team in get_test_teams():
        d, k = generate_team(team, [(x, keys[x['shared_folder_uid']]) for x in for_team])
        keys[team.team_uid] = k
        teams.append(d)

    return {
        'result': 'success',
        'full_sync': True,
        'revision': 200,
        'records': records,
        'record_meta_data': meta_data,
        'shared_folders': shared_folders,
        'teams': teams,
        'user_folder_shared_folders': [{'shared_folder_uid': x['shared_folder_uid']} for x in shared_folders],
        'user_folder_records': [{'record_uid': x['record_uid']} for x in meta_data],
        'shared_folder_folder_records': [{
            'shared_folder_uid': sf['shared_folder_uid'],
            'record_uid': sfr['record_uid']
        } for sf in shared_folders for sfr in sf['records']]
    }


TestClientVersion = 'c16.8.0'
DefaultEnvironment = 'env.company.com'
AccountUid = crypto.get_random_bytes(16)
UserName = 'some_fake_user@company.com'
UserPassword = utils.base64_url_encode(crypto.get_random_bytes(8))
UserAlternatePassword = utils.base64_url_encode(crypto.get_random_bytes(8))
UserSalt = crypto.get_random_bytes(16)
UserAlternateSalt = crypto.get_random_bytes(16)
UserIterations = 1000
UserBiometricKey = utils.generate_aes_key()
UserDataKey = utils.generate_aes_key()
UserClientKey = utils.generate_aes_key()
UserRsaPrivateKey, UserRsaPublicKey = crypto.generate_rsa_key()
UserEcPrivateKey, UserEcPublicKey = crypto.generate_ec_key()

SessionToken = crypto.get_random_bytes(64)
DeviceId = crypto.get_random_bytes(64)
DevicePrivateKey, DevicePublicKey = crypto.generate_ec_key()
DeviceCloneCode = crypto.get_random_bytes(8)
EncryptedLoginToken = crypto.get_random_bytes(64)
EncryptedLoginTokenAlternate = crypto.get_random_bytes(64)
DeviceVerificationEmailCode = '1234567890'
TwoFactorOneTimeToken = '123456'

RecordTypes = """{
  "$id": "login",
  "categories": ["login"],
  "description": "Login template",
  "fields": [
    {
      "$ref": "login"
    },
    {
      "$ref": "password"
    },
    {
      "$ref": "url"
    },
    {
      "$ref": "fileRef"
    },
    {
      "$ref": "oneTimeCode"
    }
  ]
}
"""

def generate_record(record):   # type: (Union[vault_record.KeeperRecord]) -> Tuple[dict, bytes]
    record_key = utils.generate_aes_key()
    if isinstance(record, vault_record.PasswordRecord):
        data = vault_extensions.extract_password_record_data(record)
        encrypted_data = utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(data).encode(), record_key))
        extra = vault_extensions.extract_password_record_extras(record)
        encrypted_extra = utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(extra).encode(), record_key))
        r = {
            'record_uid': record.record_uid,
            'revision': 100,
            'version': 2,
            'shared': False,
            'data': encrypted_data,
            'extra': encrypted_extra,
            'client_modified_time': utils.current_milli_time(),
        }
        if record.attachments:
            file_ids = []
            for atta in record.attachments:
                file_ids.append(atta.id)
                if atta.thumbnails:
                    for thumb in atta.thumbnails:
                        file_ids.append(thumb.id)
            r['udata'] = {
                'file_ids': file_ids
            }
    elif isinstance(record, vault_record.TypedRecord):
        data = vault_extensions.extract_typed_record_data(record, schema=None)
        encrypted_data = utils.base64_url_encode(crypto.encrypt_aes_v2(json.dumps(data).encode(), record_key))
        r = {
            'record_uid': record.record_uid,
            'revision': 100,
            'version': 3,
            'shared': False,
            'data': encrypted_data,
            'client_modified_time': utils.current_milli_time(),
        }
    elif isinstance(record, vault_record.FileRecord):
        data = vault_extensions.extract_file_record_data(record)
        encrypted_data = utils.base64_url_encode(crypto.encrypt_aes_v2(json.dumps(data).encode(), record_key))
        r = {
            'record_uid': record.record_uid,
            'revision': 100,
            'version': 4,
            'shared': False,
            'data': encrypted_data,
            'client_modified_time': utils.current_milli_time(),
        }
        if record.storage_size:
            r['file_size'] = record.storage_size
    else:
        raise Exception('Unsupported record type')
    return r, record_key


def generate_team(team, shared_folders):
    # type: (vault_types.Team, Iterable[Tuple[dict, bytes]]) -> Tuple[dict, bytes]
    team_key = utils.generate_aes_key()
    priv_key, pub_key = crypto.generate_rsa_key()
    rsa_private_key = crypto.unload_rsa_private_key(priv_key)
    t = {
        'team_uid': team.team_uid,
        'name': team.name,
        'team_key': utils.base64_url_encode(crypto.encrypt_aes_v1(team_key, UserDataKey)),
        'team_key_type': 1,
        'team_private_key': utils.base64_url_encode(crypto.encrypt_aes_v1(rsa_private_key, team_key)),
        'restrict_edit': False,
        'restrict_share': True,
        'restrict_view': False,
        'shared_folder_keys': [{
            'shared_folder_uid': x[0]['shared_folder_uid'],
            'shared_folder_key': utils.base64_url_encode(crypto.encrypt_aes_v1(x[1], team_key)),
            'key_type': 1,
        } for x in shared_folders or []]
    }
    for shared_folder, _ in shared_folders:
        if 'teams' not in shared_folder:
            shared_folder['teams'] = []
        shared_folder['teams'].append({
            'team_uid': team.team_uid,
            'name': team.name,
            'manage_records': True,
            'manage_users': False
        })
    return t, team_key


def generate_shared_folder(shared_folder, has_key, records):
    # type: (vault_types.SharedFolder, bool, Iterable[Tuple[str, bytes]]) -> Tuple[dict, bytes]
    shared_folder_key = utils.generate_aes_key()
    sf = {
        'shared_folder_uid': shared_folder.shared_folder_uid,
        'revision': 10,
        'name': utils.base64_url_encode(crypto.encrypt_aes_v1(shared_folder.name.encode(), shared_folder_key)),
        'default_manage_records': False,
        'default_manage_users': True,
        'default_can_share': False,
        'default_can_edit': True,
        'full_sync': True,
        'records': [{
            'record_uid': x[0],
            'record_key': utils.base64_url_encode(crypto.encrypt_aes_v1(x[1], shared_folder_key)),
            'can_share': False,
            'can_edit': True,
        } for x in records or []],
        'users': [],
        'teams': [],
    }
    if has_key:
        sf['shared_folder_key'] = utils.base64_url_encode(crypto.encrypt_aes_v1(shared_folder_key, UserDataKey))
        sf['key_type'] = 1
        users = sf['users']  # type: List[Dict]
        users.append({
            'username': UserName,
            'manage_records': True,
            'manage_users': True
        })

    return sf, shared_folder_key


def get_test_records():
    # type: () -> Iterable[Union[vault_record.PasswordRecord, vault_record.TypedRecord, vault_record.FileRecord]]
    r1 = vault_record.PasswordRecord()
    r1.record_uid = utils.generate_uid()
    r1.title = '1Record'
    r1.login = 'some_fake_user1@company.com'
    r1.password = 'password'
    r1.link = 'https://google.com'
    r1.notes = '1Note'
    r1.custom.append(vault_record.CustomField.create_field('name1', 'value1'))
    atta = vault_record.AttachmentFile()
    atta.id = 'ABCDEFGH'
    atta.name = '1Attachment'
    atta.key = utils.base64_url_encode(utils.generate_aes_key())
    atta.size = 1000
    r1.attachments = [atta]
    yield r1

    r2 = vault_record.PasswordRecord()
    r2.record_uid = utils.generate_uid()
    r2.title = '2Record'
    r2.login = 'some_fake_user2@company.com'
    r2.password = 'password2'
    r2.link = 'https://google.com'
    r2.notes = '2Note'
    yield r2

    f1 = vault_record.FileRecord()
    f1.record_uid = utils.generate_uid()
    f1.title = '1File'
    f1.file_name = 'abcd.txt'
    f1.size = 2000
    f1.mime_type = 'application/octet-stream'
    f1.storage_size = 2050
    yield f1

    facade = record_facades.LoginRecordFacade()
    t1 = vault_record.TypedRecord()
    t1.record_uid = utils.generate_uid()
    facade.record = t1
    facade.title = '2Record'
    facade.login = 'some_fake_user4@company.com'
    facade.password = 'password4'
    facade.url = 'https://google.com'
    facade.notes = '4Note'
    facade.file_ref.append(f1.record_uid)
    facade.record = None
    yield t1


def get_test_shared_folders():   # type: () -> Iterable[vault_types.SharedFolder]
    sf1 = vault_types.SharedFolder()
    sf1.shared_folder_uid = utils.generate_uid()
    sf1.name = '1Shared Folder'
    sf1.default_manage_records = True
    sf1.default_manage_users = False
    sf1.default_can_share = False
    sf1.default_can_edit = True
    yield sf1

    sf2 = vault_types.SharedFolder()
    sf2.shared_folder_uid = utils.generate_uid()
    sf2.name = '2Shared Folder'
    sf2.default_manage_records = False
    sf2.default_manage_users = False
    sf2.default_can_share = False
    sf2.default_can_edit = False
    yield sf2


def get_test_teams():   # type: () -> Iterable[vault_types.Team]
    t = vault_types.Team()
    t.team_uid = utils.generate_uid()
    t.name = '1Team'
    t.rsa_private_key, _ = crypto.generate_rsa_key()
    t.restrict_view = False
    t.restrict_edit = False
    t.restrict_share = True
    yield t


def get_connected_auth():    # type: () -> auth.KeeperAuth
    auth_context = auth.AuthContext()
    auth_context.username = UserName
    auth_context.session_token = crypto.get_random_bytes(64)
    auth_context.data_key = UserDataKey
    auth_context.client_key = UserClientKey
    auth_context.rsa_private_key = UserRsaPrivateKey
    auth_context.ec_private_key = UserEcPrivateKey

    storage = get_configuration_storage()
    keeper_endpoint = endpoint.KeeperEndpoint(storage)
    keeper_endpoint.client_version = TestClientVersion
    keeper_endpoint.device_name = 'Python Unit Tests'
    keeper_endpoint._communicate_keeper = None

    return auth.KeeperAuth(keeper_endpoint, auth_context)
