from typing import Optional

import json
import copy

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from unittest import mock

from keepersdk import crypto, utils, ui
from keepersdk.vault import Vault
from keepersdk.auth import Auth
from keepersdk.vault_types import PasswordRecord, SharedFolder, Team, AttachmentFile
from keepersdk.configuration import Configuration, ServerConfiguration, UserConfiguration, ConfigurationStorage, InMemoryConfiguration

_USER_NAME = 'unit.test@keepersecurity.com'
_USER_PASSWORD = utils.base64_url_encode(crypto.get_random_bytes(8))
_USER_ITERATIONS = 1000
_USER_SALT = crypto.get_random_bytes(16)
_USER_DATA_KEY = crypto.get_random_bytes(32)
_USER_CLIENT_KEY = crypto.get_random_bytes(32)

_USER_PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,7359ABCB9854B5CB781E4910662C5EF1

u1i/Mj22bT6AegV38qTsz0mK/QFbGpveS9dq4GXkYVA5JjqowcVsl1HUq2mIhDmW
wYRhkqGWD6IJkt++mDIpv74VKYYuzxTVvt4V46LS/mXn9xqO8g8Cy1qxWznRBPZe
a6/qziQpSI1R4PltIcD1gQHPIJiHINOi4Zi1GT6FTRzZwQ+08rOFfRchvP/rG8hX
KgLywsk9p44exMNJBJhOVTs6UeC4zGdMxNN++Qa+3o+6G8FVgyR4KNGqcFVoYGe6
L5K5KoJz4LwhUy3NDL9TSftxqvXsbiFtUw4BSEYjdyDYQz/ytpFkyGJIzn7vutx+
XbEIMRi6RR2qObI9TdiA5w7sOthvCiGbpzqlH6b++pIRNYiUPe+Ec8SeEbkM8wZB
IFx6xCpDKZQPyCnHngwYIw/iCXqO5UyJjDCnDHOVpMi/BbMJsKp7U+qcrUmN9gUr
VMFRlUZpps5Im3wu3gebZ6Fu41JYK2LqcgEOnh0EbeeZIvH3+uv/QIHdJPYSbsMU
Ns2KJQc+n4PsZa7kZf/CGAq926Y302o9SV2pX1GAcwoHJWkfukZhpt3ikJSrnHVD
FAIZbA0xt4XdbDMVg5T6Er+q1IO1zrZeQ/NLsRR+/JLz3+DvtIKrVMTLtGbl/VV4
rROt9l6YnF2F8CMaMz68v+19vzo1zEob/WD/8Ye3YQq66meJ/+NjwyTmMrZxsO/l
FHeDgDs1r2Nc1uC2/n1UiiZyFTaBzkj/5QUnpBm33V/P63+pN6cw0qEvjNEwdIOC
d5Ohky1d1ayhSeVHkx1ZYcSTriicgWcWTOV+zckJ+VAqvSCZV4A+NMqZGVzPhMgC
h9GWvIXfMDhXIDzBsQz2W3zseJFSzL4av8b/AxTDapOeS9M8FzsbEDJC7YfiLVWK
6bFOLr2dg5Lm41iyWmp7NK2+IUFN15DgMIbHcpfD24F+cs73hjE3E56rsb8dBifG
Q1izqwFiopK+1z9C/EWBmmY3AcyqjXEQl3DWnL2IbYnhmm/SN040BGVZKJcUBUlk
b7RPQF+uZWlM8EWLTqCZQUfl3bogxOcFryyElBPDVRq4Z/x4di2FuUbmI/Mbs1g7
PiBWKIC8CHk3sLezXgMn1thkKsRI3xN+jZcGTZ6lhTVKUAbbW8mqRzBtyjPHbjUC
9PRSeJRDc10ZYnyWhLXa2lSgY12obXNuxLi8eKg6VuBnVzh4CvjOmJY3NlA5xsUi
YLl49YLLQqBU2IwrgqYm+7n2D8PmnhwPUPj2shNoIi9gtAhx8n0pyypgzd8iTtQZ
3IxO1zaNjJOal4er299DcoBsZ5cZ7EU6ltwtUCNqGyaVWwSqjAKtiPGpjT/eEAeL
KLzX+F5r+dUUsy5m8ds+6TUWDxLaqT8PcugnUxT8f3JokODv7JHSiogB1ETeczKS
RJfJH63edAQLxl+rayIqsTuUntmMNgE3olQWexCChX9b8xW6OzVgw8jU6WX0OGOB
5qkDxT9de8CpseIymuDX8AYIpPxIHJdigTBBfYp34hPAKuBpAwDPNS1FiOZYYZSB
84VHEOeXkUpBgAGQwphDZITltMDnssSGPbCX9EHM5+mNVkmQw+SDJbcgXm0jNVtC
-----END RSA PRIVATE KEY-----
'''
_PRIVATE_KEY_PASSWORD = 'E,{-qhsm;<cq]3D(3H5K/'
_USER_PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0AjmBXo371pYmvS1NM
8nXlbAv5qUbPYuV6KVwKjN3T8WX5K6HDGl3+ylAbI02vIzKue+gDbjo1wUGp2qhA
Nc1VxllLSWnkJmwbuGUTEWp4ANjusoMhPvEwna1XPdlrSMdsKokjbP9xbguPdvXx
5oBaqArrrGEg+36Vi7miA/g/UT4DKcryglD4Xx0H9t5Hav+frz2qcEsyh9FC0fNy
on/uveEdP2ac+kax8vO5EeVfBzOdw+WPaBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm0
38JuMwHChTK29H9EOlqbOOuzYA1ENzL88hELpe+kl4RmpNS94BJDssikFFbjoiAV
fwIDAQAB
-----END PUBLIC KEY-----
'''

_SESSION_TOKEN = utils.base64_url_encode(crypto.get_random_bytes(64))
_DEVICE_ID = crypto.get_random_bytes(64)

_2FA_ONE_TIME_TOKEN = '123456'
_2FA_DEVICE_TOKEN = utils.base64_url_encode(crypto.get_random_bytes(32))

_IMPORTED_PRIVATE_KEY = serialization.load_pem_private_key(_USER_PRIVATE_KEY.encode('utf-8'), _PRIVATE_KEY_PASSWORD.encode('utf-8'), default_backend())
_DER_PRIVATE_KEY = _IMPORTED_PRIVATE_KEY.private_bytes(encoding=serialization.Encoding.DER,
                                                       format=serialization.PrivateFormat.PKCS8,
                                                       encryption_algorithm=serialization.NoEncryption())
_ENCRYPTED_PRIVATE_KEY = utils.base64_url_encode(crypto.encrypt_aes_v1(_DER_PRIVATE_KEY, _USER_DATA_KEY))

_IMPORTED_PUBLIC_KEY = serialization.load_pem_public_key(_USER_PUBLIC_KEY.encode('utf-8'), default_backend())
_DER_PUBLIC_KEY = _IMPORTED_PUBLIC_KEY.public_bytes(encoding=serialization.Encoding.DER,
                                                     format=serialization.PublicFormat.PKCS1)
_ENCODED_PUBLIC_KEY = utils.base64_url_encode(_DER_PUBLIC_KEY)

_V2_DERIVED_KEY = crypto.derive_keyhash_v2('data_key', _USER_PASSWORD, _USER_SALT, _USER_ITERATIONS)
_dk = crypto.encrypt_aes_v2(_USER_DATA_KEY, _V2_DERIVED_KEY)
_ENCRYPTED_DATA_KEY = utils.base64_url_encode(_dk)

_V1_DERIVED_KEY = crypto.derive_key_v1(_USER_PASSWORD, _USER_SALT, _USER_ITERATIONS)
_enc_iter = int.to_bytes(_USER_ITERATIONS, length=3, byteorder='big', signed=False)
_enc_iv = crypto.get_random_bytes(16)
_enc_dk = b'\x01' + _enc_iter + _USER_SALT + crypto.encrypt_aes_v1(_USER_DATA_KEY + _USER_DATA_KEY, _V1_DERIVED_KEY, _enc_iv, use_padding=False)
_ENCRYPTION_PARAMS = utils.base64_url_encode(_enc_dk)


class TestAuthUI(ui.AuthUI):
    def confirmation(self, information):  # type: (str) -> bool
        return True

    def get_new_password(self, matcher):  # type: (ui.PasswordRuleMatcher) -> Optional[str]
        return 'qwerty'

    def get_twofactor_code(self, provider):  # type: (ui.TwoFactorChannel) -> str
        return '123456'


class VaultEnvironment:
    def __init__(self):
        self.user = _USER_NAME
        self.password = _USER_PASSWORD
        self.iterations = _USER_ITERATIONS
        self.salt = _USER_SALT
        self.data_key = _USER_DATA_KEY
        self.public_key = _IMPORTED_PUBLIC_KEY
        self.encoded_public_key = _ENCODED_PUBLIC_KEY
        self.session_token = _SESSION_TOKEN
        self.device_id = _DEVICE_ID
        self.one_time_token = _2FA_ONE_TIME_TOKEN
        self.device_token = _2FA_DEVICE_TOKEN
        self.encrypted_private_key = _ENCRYPTED_PRIVATE_KEY
        self.encrypted_data_key = _ENCRYPTED_DATA_KEY
        self.encryption_params = _ENCRYPTION_PARAMS
        self.client_key = _USER_CLIENT_KEY
        self.revision = _REVISION


def get_configuration_storage():
    # type: () -> ConfigurationStorage
    server_conf = ServerConfiguration(server='test.keepersecurity.com', device_id=_DEVICE_ID, server_key_id=1)
    user_conf = UserConfiguration(username=_USER_NAME, password=_USER_PASSWORD)
    config = Configuration()
    config.last_server = server_conf.server
    config.last_username = user_conf.username
    config.users.append(user_conf)
    config.servers.append(server_conf)
    return InMemoryConfiguration(config)


def get_auth_context():
    # type: () -> Auth
    config = get_configuration_storage()
    return Auth(TestAuthUI(), config)


def get_connected_auth_context():
    # type: () -> Auth
    auth = get_auth_context()
    config = auth.storage.get_configuration()
    user_config = config.get_user_configuration(config.last_username)
    auth.username = user_config.username
    key_hash = crypto.derive_keyhash_v1(user_config.password, _USER_SALT, _USER_ITERATIONS)
    auth.auth_response = utils.base64_url_encode(key_hash)
    auth.twofactor_token = user_config.two_factor_token
    auth.client_key = _USER_CLIENT_KEY
    auth.data_key = _USER_DATA_KEY
    auth.private_key = _IMPORTED_PRIVATE_KEY
    auth.session_token = _SESSION_TOKEN

    return auth

def get_vault():
    # type: () -> Vault
    auth = get_connected_auth_context()
    with mock.patch('keepersdk.auth.Auth.execute_auth_command') as mock_comm:
        mock_comm.return_value = get_sync_down_response()
        return Vault(auth)


_REVISION = 100
_RECORDS = []
_RECORD_METADATA = []
_SHARED_FOLDERS = []
_USER_FOLDERS = []
_USER_FOLDER_RECORDS = []
_USER_FOLDER_SHARED_FOLDER = []
_TEAMS = []

def get_sync_down_response():
    return {
        'result': 'success',
        'result_code': '',
        'message': '',
        'full_sync': True,
        'revision': _REVISION,
        'records': copy.deepcopy(_RECORDS),
        'record_meta_data': copy.deepcopy(_RECORD_METADATA),
        'shared_folders': copy.deepcopy(_SHARED_FOLDERS),
        'teams': copy.deepcopy(_TEAMS),
        'user_folders': copy.deepcopy(_USER_FOLDERS),
        'user_folder_records': copy.deepcopy(_USER_FOLDER_RECORDS),
        'user_folder_shared_folders': copy.deepcopy(_USER_FOLDER_SHARED_FOLDER),
    }


def register_record(record, key_type=None):
    # type: (PasswordRecord, Optional[int]) -> bytes

    record_dict = PasswordRecord.dump(record)
    record_key = crypto.get_random_bytes(32) if key_type != 0 else _USER_DATA_KEY
    data = json.dumps(record_dict['data']).encode('utf-8')
    data = crypto.encrypt_aes_v1(data, record_key)
    rec_object = {
        'record_uid': record.record_uid,
        'revision': record.revision if (0 < record.revision <= _REVISION) else _REVISION,
        'version': 2 if key_type != 0 else 1,
        'shared': key_type not in [0, 1],
        'data': utils.base64_url_encode(data)
    }
    if 'extra' in record_dict:
        extra = json.dumps(record_dict['extra']).encode('utf-8')
        rec_object['extra'] = utils.base64_url_encode(crypto.encrypt_aes_v1(extra, record_key))
    if 'udata' in rec_object:
        rec_object['udata'] = json.dumps(rec_object['udata'])

    _RECORDS.append(rec_object)

    meta_data = {
        'record_uid': record.record_uid,
        'owner': key_type in [0, 1],
        'can_share': key_type == 1,
        'can_edit': key_type == 1,
        'record_key_type': key_type
    }

    if key_type == 0:
        _RECORD_METADATA.append(meta_data)
    if key_type == 1:
        meta_data['record_key'] = utils.base64_url_encode(crypto.encrypt_aes_v1(record_key, _USER_DATA_KEY))
        _RECORD_METADATA.append(meta_data)
    elif key_type == 2:
        meta_data['record_key'] = utils.base64_url_encode(crypto.encrypt_rsa(record_key, _IMPORTED_PUBLIC_KEY))
        _RECORD_METADATA.append(meta_data)

    return record_key


def register_records_to_folder(folder_uid, record_uids):
    # type: (Optional[str], list) -> None
    for record_uid in record_uids:
        ufr = {
            'record_uid': record_uid
        }
        if folder_uid:
            ufr['folder_uid'] = folder_uid
        _USER_FOLDER_RECORDS.append(ufr)


def register_shared_folder(shared_folder, records):
    # type: (SharedFolder, dict) -> bytes

    shared_folder_key = crypto.get_random_bytes(32)
    sf = {
        'shared_folder_uid': shared_folder.shared_folder_uid,
        'key_type': 1,
        'shared_folder_key': utils.base64_url_encode(crypto.encrypt_aes_v1(shared_folder_key, _USER_DATA_KEY)),
        'name': utils.base64_url_encode(crypto.encrypt_aes_v1(shared_folder.name.encode('utf-8'), shared_folder_key)),
        'is_account_folder': False,
        'manage_records': False,
        'manage_users': False,
        'default_manage_records': True,
        'default_manage_users': True,
        'default_can_edit': True,
        'default_can_share': True,
        'full_sync': True,
        'records': [{
            'record_uid': x[0],
            'record_key': utils.base64_url_encode(crypto.encrypt_aes_v1(x[1], shared_folder_key)),
            'can_share': False,
            'can_edit': False
        } for x in records.items()],
        'users': [{
            'username': _USER_NAME,
            'manage_records': True,
            'manage_users': True
        }],
        'revision': 5
    }
    _SHARED_FOLDERS.append(sf)

    return shared_folder_key


def register_team(team, key_type, sfs=None):
    # type: (Team, int, dict) -> bytes
    team_key = crypto.get_random_bytes(32)
    encrypted_team_key = crypto.encrypt_aes_v1(team_key, _USER_DATA_KEY) if key_type == 1 else crypto.encrypt_rsa(team_key, _IMPORTED_PUBLIC_KEY)
    t = {
        'team_uid': team.team_uid,
        'name': team.name,
        'team_key_type': key_type,
        'team_key': utils.base64_url_encode(encrypted_team_key),
        'team_private_key': utils.base64_url_encode(crypto.encrypt_aes_v1(_DER_PRIVATE_KEY, team_key)),
        'restrict_edit': team.restrict_edit,
        'restrict_share': team.restrict_share,
        'restrict_view': team.restrict_view,
    }
    _TEAMS.append(t)

    if sfs:
        t['shared_folder_keys'] = [{
            'shared_folder_uid': x[0],
            'key_type': 1,
            'shared_folder_key': utils.base64_url_encode(crypto.encrypt_aes_v1(x[1], team_key))
        } for x in sfs.items()]

        sf_uids = set()
        for uid in sfs:
            sf_uids.add(uid)
        for sf in _SHARED_FOLDERS:
            if sf['shared_folder_uid'] in sf_uids:
                if 'teams' not in sf:
                    sf['teams'] = []
                sf['teams'].append({
                    'team_uid': team.team_uid,
                    'name': team.name,
                    'manage_records': key_type == 1,
                    'manage_users': key_type == 1
                })

    return team_key


def generate_data():
    r1 = PasswordRecord()
    r1.record_uid = utils.base64_url_encode(crypto.get_random_bytes(16))
    r1.title = 'Record 1'
    r1.login = 'user1@keepersecurity.com'
    r1.password = 'password1'
    r1.link = 'https://keepersecurity.com/1'
    r1.set_field('field1', 'value1')
    r1.notes = 'note1'
    atta = AttachmentFile()
    atta.id = 'ABCDEFGH'
    atta.name = 'Attachment 1'
    atta.key = crypto.get_random_bytes(32)
    atta.size = 1000
    r1.attachments = [atta]
    r1.revision = 1
    r1_key = register_record(r1, 1)

    r2 = PasswordRecord()
    r2.record_uid = utils.base64_url_encode(crypto.get_random_bytes(16))
    r2.title = 'Record 2'
    r2.login = 'user2@keepersecurity.com'
    r2.password = 'password2'
    r2.login_url = 'https://keepersecurity.com/2'
    r2.set_field('field2', 'value2')
    r2.notes = 'note2'
    r2.revision = 2
    r2_key = register_record(r2, 2)

    register_records_to_folder(None, [r1.record_uid, r2.record_uid])

    r3 = PasswordRecord()
    r3.record_uid = utils.base64_url_encode(crypto.get_random_bytes(16))
    r3.title = 'Record 3'
    r3.login = 'user3@keepersecurity.com'
    r3.password = 'password3'
    r3.login_url = 'https://keepersecurity.com/3'
    r3.revision = 3
    r3_key = register_record(r3)

    sf1 = SharedFolder()
    sf1.shared_folder_uid = utils.base64_url_encode(crypto.get_random_bytes(16))
    sf1.default_manage_records = False
    sf1.default_manage_users = False
    sf1.default_can_edit = False
    sf1.default_can_share = False
    sf1.name = 'Shared Folder 1'
    sf1_key = register_shared_folder(sf1, {
        r3.record_uid: r3_key
    })
    register_records_to_folder(sf1.shared_folder_uid, [r3.record_uid])
    _USER_FOLDER_SHARED_FOLDER.append({'shared_folder_uid': sf1.shared_folder_uid})

    t1 = Team()
    t1.team_uid = utils.base64_url_encode(crypto.get_random_bytes(16))
    t1.name = 'Team 1'
    t1.restrict_edit = True
    t1.restrict_share = True
    t1.restrict_view = False

    register_team(t1, 1, {
        sf1.shared_folder_uid: sf1_key
    })

    folder_key = crypto.get_random_bytes(32)
    _USER_FOLDERS.append({
        'folder_uid': utils.base64_url_encode(crypto.get_random_bytes(16)),
        'key_type': 1,
        'user_folder_key': utils.base64_url_encode(crypto.encrypt_aes_v1(folder_key, _USER_DATA_KEY)),
        'revision': 200,
        'type': 'user_folder',
        'data': crypto.encrypt_aes_v1(json.dumps({'name': 'User Folder 1'}).encode('utf-8'), folder_key)
    })


generate_data()
