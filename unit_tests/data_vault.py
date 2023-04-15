import json
from typing import Iterable, Union, Dict, Tuple, List

from keepersdk import crypto, utils
from keepersdk.login import configuration, endpoint, auth
from keepersdk.proto import AccountSummary_pb2, APIRequest_pb2, SyncDown_pb2, record_pb2
from keepersdk.vault import record_facades, vault_record, vault_types, vault_extensions


def get_configuration_storage():
    config = configuration.KeeperConfiguration()
    config.last_server = DefaultEnvironment
    config.last_login = UserName
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
    pk = utils.base64_url_decode(UserRsaPrivateKey)
    result.keysInfo.encryptedPrivateKey = crypto.encrypt_aes_v1(pk, UserDataKey)
    pk = utils.base64_url_decode(UserEcPrivateKey)
    result.keysInfo.encryptedEccPrivateKey = crypto.encrypt_aes_v2(pk, UserDataKey)
    result.keysInfo.eccPublicKey = utils.base64_url_decode(UserEcPublicKey)
    config = keeper_endpoint.get_configuration_storage().get()
    for dc in config.devices().list():
        di = AccountSummary_pb2.DeviceInfo()
        di.clientVersion = TestClientVersion
        di.deviceName = 'Test Device'
        di.deviceStatus = APIRequest_pb2.DEVICE_OK
        di.encryptedDeviceToken = utils.base64_url_decode(dc.device_token)
        di.devicePublicKey = utils.base64_url_decode(dc.public_key)
    return result


def sync_down_response():  # type: () -> SyncDown_pb2.SyncDownResponse
    keys = {}            # type: Dict[bytes, bytes]
    records = []         # type: List[SyncDown_pb2.Record]
    meta_data = []       # type: List[SyncDown_pb2.RecordMetaData]
    nsd = []             # type: List[SyncDown_pb2.NonSharedData]
    for_sf = []          # type: List[SyncDown_pb2.Record]

    for record in get_test_records():
        d, k = generate_record(record)
        keys[d.recordUid] = k
        has_shared_folder = len(records) in {2, 3}
        has_direct_share = len(records) == 3

        if has_shared_folder:
            d.shared = True
            for_sf.append(d)
        if not has_shared_folder or has_direct_share:
            d.shared = has_direct_share
            md = SyncDown_pb2.RecordMetaData()
            md.recordUid = utils.base64_url_decode(record.record_uid)
            md.owner = not has_direct_share
            md.canEdit = not has_direct_share
            md.canShare = not has_direct_share
            if has_direct_share:
                rsa_public_key = crypto.load_rsa_public_key(utils.base64_url_decode(UserRsaPublicKey))
                md.recordKey = crypto.encrypt_rsa(k, rsa_public_key)
                md.recordKeyType = record_pb2.ENCRYPTED_BY_PUBLIC_KEY
            elif isinstance(record, vault_record.PasswordRecord):
                md.recordKey = crypto.encrypt_aes_v1(k, UserDataKey)
                md.recordKeyType = record_pb2.ENCRYPTED_BY_DATA_KEY
            else:
                md.recordKey = crypto.encrypt_aes_v2(k, UserDataKey)
                md.recordKeyType = record_pb2.ENCRYPTED_BY_DATA_KEY_GCM
            meta_data.append(md)
        if has_direct_share:
            non_shared = SyncDown_pb2.NonSharedData()
            non_shared.recordUid = d.recordUid
            data = json.dumps({'favorite': True}).encode()
            non_shared.data = crypto.encrypt_aes_v1(data, UserDataKey)
            nsd.append(non_shared)
        records.append(d)

    shared_folders = []            # type: List[SyncDown_pb2.SharedFolder]
    shared_folder_records = []     # type: List[SyncDown_pb2.SharedFolderRecord]
    record_keys = []               # type: List[Tuple[SyncDown_pb2.Record, bytes]]
    for_team = []                  # type: List[SyncDown_pb2.SharedFolder]
    for shared_folder in get_test_shared_folders():
        use_key = len(shared_folders) == 0
        d, k = generate_shared_folder(shared_folder, use_key)
        if not use_key:
            for_team.append(d)
        keys[d.sharedFolderUid] = k
        shared_folders.append(d)
        record_keys.clear()
        if len(shared_folders) == 0:
            record_keys.extend(((x, keys[x.recordUid]) for x in for_sf))
        else:
            record = for_sf[-1]
            record_keys.append((record, keys[record.recordUid]))

        if len(record_keys) > 0:
            shared_folder_records.extend(generate_shared_folder_records((d.sharedFolderUid, k), record_keys))

    teams = []                   # type: List[SyncDown_pb2.Team]
    shared_folder_teams = []     # type: List[SyncDown_pb2.SharedFolderTeam]
    for team in get_test_teams():
        t, sf_keys, k = generate_team(team, [(x, keys[x.sharedFolderUid]) for x in for_team])
        keys[t.teamUid] = k
        teams.append(t)
        shared_folder_teams.extend(sf_keys)

    rs = SyncDown_pb2.SyncDownResponse()
    rs.continuationToken = crypto.get_random_bytes(64)
    rs.hasMore = False
    rs.cacheStatus = SyncDown_pb2.CLEAR
    rs.records.extend(records)
    rs.recordMetaData.extend(meta_data)
    rs.nonSharedData.extend(nsd)
    rs.sharedFolders.extend(shared_folders)
    for sf in shared_folders:
        sfu = SyncDown_pb2.SharedFolderUser()
        sfu.sharedFolderUid = sf.sharedFolderUid
        sfu.accountUid = AccountUid
        sfu.manageRecords = True
        sfu.manageUsers = True
        rs.sharedFolderUsers.append(sfu)

    rs.sharedFolderRecords.extend(shared_folder_records)
    rs.sharedFolderTeams.extend(shared_folder_teams)
    rs.teams.extend(teams)
    u = SyncDown_pb2.User()
    u.username = UserName
    u.accountUid = AccountUid
    rs.users.append(u)

    return rs


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


def generate_record(record):   # type: (vault_record.KeeperRecord) -> Tuple[SyncDown_pb2.Record, bytes]
    record_key = utils.generate_aes_key()
    if isinstance(record, vault_record.PasswordRecord):
        data = vault_extensions.extract_password_record_data(record)
        encrypted_data = crypto.encrypt_aes_v1(json.dumps(data).encode(), record_key)
        extra = vault_extensions.extract_password_record_extras(record)
        encrypted_extra = crypto.encrypt_aes_v1(json.dumps(extra).encode(), record_key)
        r = SyncDown_pb2.Record()
        r.recordUid = utils.base64_url_decode(record.record_uid)
        r.revision = 100
        r.version = 2
        r.shared = False
        r.data = encrypted_data
        r.extra = encrypted_extra
        r.clientModifiedTime = utils.current_milli_time()
        if record.attachments:
            file_ids = []
            for atta in record.attachments:
                file_ids.append(atta.id)
                if atta.thumbnails:
                    for thumb in atta.thumbnails:
                        file_ids.append(thumb.id)
            r.udata = json.dumps({'file_ids': file_ids})
    elif isinstance(record, vault_record.TypedRecord):
        data = vault_extensions.extract_typed_record_data(record, schema=None)
        encrypted_data = crypto.encrypt_aes_v2(json.dumps(data).encode(), record_key)
        r = SyncDown_pb2.Record()
        r.recordUid = utils.base64_url_decode(record.record_uid)
        r.revision = 100
        r.version = 3
        r.shared = False
        r.data = encrypted_data
        r.clientModifiedTime = utils.current_milli_time()
    elif isinstance(record, vault_record.FileRecord):
        data = vault_extensions.extract_file_record_data(record)
        encrypted_data = crypto.encrypt_aes_v2(json.dumps(data).encode(), record_key)
        r = SyncDown_pb2.Record()
        r.recordUid = utils.base64_url_decode(record.record_uid)
        r.revision = 100
        r.version = 4
        r.shared = False
        r.data = encrypted_data
        r.clientModifiedTime = utils.current_milli_time()
        if record.storage_size:
            r.fileSize = record.storage_size
    else:
        raise Exception('Unsupported record type')
    return r, record_key


def generate_team(
        team,           # type: vault_types.Team
        shared_folders  # type: Iterable[Tuple[SyncDown_pb2.SharedFolder, bytes]]
    ):                  # type: (...) -> Tuple[SyncDown_pb2.Team, List[SyncDown_pb2.SharedFolderTeam], bytes]
    team_key = utils.generate_aes_key()
    rsa_private_key = utils.base64_url_decode(TeamPrivateKey)
    t = SyncDown_pb2.Team()
    t.teamUid = utils.base64_url_decode(team.team_uid)
    t.name = team.name
    t.teamKey = crypto.encrypt_aes_v1(team_key, UserDataKey)
    t.teamKeyType = record_pb2.ENCRYPTED_BY_DATA_KEY
    t.teamPrivateKey = crypto.encrypt_aes_v1(rsa_private_key, team_key)
    t.restrictView = False
    t.restrictEdit = False
    t.restrictShare = False
    for sf, shared_folder_key in shared_folders:
        sfk = SyncDown_pb2.SharedFolderKey()
        sfk.sharedFolderUid = sf.sharedFolderUid
        sfk.sharedFolderKey = crypto.encrypt_aes_v1(shared_folder_key, team_key)
        sfk.keyType = record_pb2.ENCRYPTED_BY_DATA_KEY
        t.sharedFolderKeys.append(sfk)

    sfts = []     # type: List[SyncDown_pb2.SharedFolderTeam]
    for sf, _ in shared_folders:
        sft = SyncDown_pb2.SharedFolderTeam()
        sft.sharedFolderUid = sf.sharedFolderUid
        sft.teamUid = utils.base64_url_decode(team.team_uid)
        sft.manageRecords = True
        sft.manageUsers = False
        sfts.append(sft)

    return t, sfts, team_key


def generate_shared_folder_records(sh_info, records):
    """
    :param sh_info:
    :type sh_info:  Tuple[bytes,  bytes]
    :param records:
    :type records: Iterable[Tuple[SyncDown_pb2.Record, bytes]]
    :return:
    :rtype: List[SyncDown_pb2.SharedFolderRecord]
    """
    result = []   # type: List[SyncDown_pb2.SharedFolderRecord]
    shared_folder_uid, shared_folder_key = sh_info
    for record, record_key in records:
        sfr = SyncDown_pb2.SharedFolderRecord()
        sfr.sharedFolderUid = shared_folder_uid
        sfr.recordUid = record.recordUid
        if record.version == 2:
            sfr.recordKey = crypto.encrypt_aes_v1(record_key, shared_folder_key)
        else:
            sfr.recordKey = crypto.encrypt_aes_v2(record_key, shared_folder_key)
        sfr.canShare = False
        sfr.canEdit = True
        sfr.ownerAccountUid = AccountUid
        sfr.owner = True
        result.append(sfr)

    return result


def generate_shared_folder(shared_folder, has_key):
    # type: (vault_types.SharedFolder, bool) -> Tuple[SyncDown_pb2.SharedFolder, bytes]
    shared_folder_key = utils.generate_aes_key()
    sf = SyncDown_pb2.SharedFolder()
    sf.sharedFolderUid = utils.base64_url_decode(shared_folder.shared_folder_uid)
    sf.revision = 10
    if has_key:
        sf.sharedFolderKey = crypto.encrypt_aes_v1(shared_folder_key, UserDataKey)
        sf.keyType = record_pb2.ENCRYPTED_BY_DATA_KEY
    sf.name = crypto.encrypt_aes_v1(shared_folder.name.encode(), shared_folder_key)
    data = {'name': shared_folder.name}
    sf.data = crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), shared_folder_key)
    sf.defaultManageRecords = False
    sf.defaultManageUsers = True
    sf.defaultCanEdit = True
    sf.defaultCanReshare = False
    sf.cacheStatus = SyncDown_pb2.CacheStatus.CLEAR
    sf.ownerAccountUid = AccountUid

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
    t.rsa_private_key = crypto.load_rsa_private_key(utils.base64_url_decode(TeamPrivateKey))
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
    auth_context.rsa_private_key = crypto.load_rsa_private_key(utils.base64_url_decode(UserRsaPrivateKey))
    auth_context.ec_private_key = crypto.load_ec_private_key(utils.base64_url_decode(UserEcPrivateKey))

    storage = get_configuration_storage()
    keeper_endpoint = endpoint.KeeperEndpoint(storage)
    keeper_endpoint.client_version = TestClientVersion
    keeper_endpoint.device_name = 'Python Unit Tests'
    keeper_endpoint._communicate_keeper = None

    return auth.KeeperAuth(keeper_endpoint, auth_context)


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
UserRsaPrivateKey = """MIIEowIBAAKCAQEAlnlA0KOAMerd4TADRrm0M3v0gBbZbP7RZN1MQ7nmENiDBCe
FIbK5VnThQIs5rRHtXKrO0_wklZ74I6eS8mX_jpXfLkkKfLRN1AsJs-VCgrYRvu
NkVLBl9K9Ywv9mRoxiHYgg5FujW6Q9k-GYBVD5P2Bk74OnSqQAXvXeKJmYpnrtb
PFEMZzNfTDxdPCdGfEFrZLp_JCJKbXQLzxwG8ck_VqR0JMR7KIBw4nmTVEaa3wP
8GUvjO1BJdy_iSIyzvGHgcyi7LTaG1Rl-6_xmgGtJ92zS8aZFkzqCw9t7VFpaVA
9k_eIXZOK-5uOKj1Heq8k2BkNU6Gaa-10rsXKt6ldMwIDAQABAoIBAEjeoHJJc6
f41wmaAEQsY2V5Vk7_gbzEbDAd8TRtHsqyp0QIRXMrw5BoWrswkTZMk7fIKhBDr
43bpcxSdxm3Jnrs_l9CVPdOM9CHpeO-FycIt_BK24gdwsorbl9EYsmwa0Vk6pTc
AfC7yWxHmCCe9Y1pB4hsJ8RARsO16qebtm6MJDg6ycEGo_QuMsM_PCNA6CtAByl
Rsgta-M3O7gZ0iVQvUxQlWyd9ejilJEYpYXWh21z_U9iFSnjZRFJxhxiHnQBeEe
y9mnSVf2oAxnmUDfG9PYva21_EM0dEFTWcUvoYb_tl5uYkIUqd5hUZRXfPFlDu-
LFL2hW3DuIzQg3UQo0CgYEAxwrXuaBpDWc7PMwWa_dtASbnIsPIRfcMdZpR19cd
B9TnP993J25l7IReyKQSMrASBC7Vp4kPGxz_NPyclaM4bpOyRYY123vxfK2XVsf
QNJNbaCzLA0w3GoNVOxlERRWHX3GCsp4Mfpl-RD8QoHKEjosHG6PfYhXJJQXuli
JyOg8CgYEAwYhvJcxNxqcwng8BncMSiQ9b07rJLdmyE3v3QYidCEXd1fLtscXmy
y2dDyfb7q5VGBYe7MI8fZNcDLLo9_mnlupsmuoci6NLeJiz3dgSwDagFmp5jG-I
pwGLMXKMFzAqRi1pQvrXhFp5ZhPhqzi8gMnV02-vSSNFenwZuqRSHp0CgYBWnwB
c91NgkuFzxvmnCOm2S6DhP0TkNeyFLaCahzJKGzx8TpsDXQccVEsPlF-bEYb1rR
AsNfiN-yORgrH-aScA8GPv38WGfD0O3ljzWkfg6ZQpFP1QtRVyA1_PNWLBken0_
mg7pY6YdeI-fxeUS-ImSpjQTZPEkuiTpS48xkbhvwKBgQCyLVsvMH52o1yWWHiD
d6Jr_3DqaPBpPyC84YfNlOoGQNSw8jw2TF5ktvT_jBHnGCeNymfkUBuC_ZVkt57
XFsldnywoH9vyD4AfYm9Okm0I_AG9QX_wdIsaPsiY2L3zZ0u0WoCrwueCmg1klm
9QxSZ_Z9NuG0gFDO0djH3foQNd3QKBgAJ8URi1QhLfUE0Sl2SU_vk4K1-aOzxVR
zNkRRH7CxD8dqrOD79Lb8HKlXUliPghr5C_KhuaaqRKYdrldDyOCnUhPTn10r16
Bzwv_LNNoscNhlPnwPjC-BxZ39Q4aORzEXB4nq8YAnF4DghKBrqaah_mOXOOHOn
uBJGxH8uBIfRN"""
UserRsaPublicKey = """MIIBCgKCAQEAlnlA0KOAMerd4TADRrm0M3v0gBbZbP7RZN1MQ7nmENiDBCeFIbK
5VnThQIs5rRHtXKrO0_wklZ74I6eS8mX_jpXfLkkKfLRN1AsJs-VCgrYRvuNkVL
Bl9K9Ywv9mRoxiHYgg5FujW6Q9k-GYBVD5P2Bk74OnSqQAXvXeKJmYpnrtbPFEM
ZzNfTDxdPCdGfEFrZLp_JCJKbXQLzxwG8ck_VqR0JMR7KIBw4nmTVEaa3wP8GUv
jO1BJdy_iSIyzvGHgcyi7LTaG1Rl-6_xmgGtJ92zS8aZFkzqCw9t7VFpaVA9k_e
IXZOK-5uOKj1Heq8k2BkNU6Gaa-10rsXKt6ldMwIDAQAB"""
UserEcPrivateKey = 'eT-2z_rQ_wTL5zNxe8204nbL_KUP_LM3WMsDTy52A0o'
UserEcPublicKey = 'BLua58lzUKZLOkNcVDRfTauy5K_6fOH5UDePef2Q4b-Pr82u_kqge96mDFsX7ML0nFHl57hhPJUBp9_UBvJ7avk'

SessionToken = crypto.get_random_bytes(64)
DeviceId = crypto.get_random_bytes(64)
DevicePrivateKey, DevicePublicKey = crypto.generate_ec_key()
DeviceCloneCode = crypto.get_random_bytes(8)
EncryptedLoginToken = crypto.get_random_bytes(64)
EncryptedLoginTokenAlternate = crypto.get_random_bytes(64)
DeviceVerificationEmailCode = '1234567890'
TwoFactorOneTimeToken = '123456'

TeamPrivateKey = """MIIEowIBAAKCAQEA7s5lRoIIN3Cn87dhQkcqlQLW6l9UoycB5samXtI-F5pp1ym
0QWZC5JMX2m8wg_VjzCpe9KSv_3mtVOt8BD_NER_5cpnXamJRBpVSwk3rWyHjZm
mBsPYdJGJ1AiBtEhNGfYtL6Munxuskahc_DdXcFtFSFIYlFp-iPJs3TVk1wiovL
5aeedf52Fm9NaMtcl8qmbKTxaFrbdIs0cxdHUjIuA1eqo4BQ1qcF8UsDR3iSQwi
oRwjNEcEJKDxfWaA6IUYnbWz-5c2IgRqaY04a99i6cpf04wGhGHHc_kJSROvIrL
x8uhSWJVFU5N3jdtBgWgwb7-gzRy4Ty4MruGVbTLWuwIDAQABAoIBAAL4QBwrW8
zMstn-CtCXL_lgaqnJe7T3tDdZexIszSbf_bb2Rs6VZfmPtrk5rsHFWHNeh4XFU
ob7zWMD9qva20L-QcziCuLAzD8ntjrCW03r0vcgEsPPm7crHkdjfde-s562D8Ca
X8DChdZn6ZnTcgQ6oCmvLWDlpU_Zokts85UxiPRdDb2Qcbtry1buTuHXmk_szC0
6Lj5WJ6_xcHsSHD3vgzW5Gw-bXqxi4mOci0uWd_MSqB4UAmcXpjPN4c6v1o_W6Z
D6LRGaHawGRWc25mQBWsP4htrMsKivcN12l4HJIMVNZbEAx3Jky3zNj-od0BsVb
jSX4DmjtCpiSNv5ahkCgYEA-DOngOGIv27EOkk5lgzRvtL64hqagYSoO2D26cHC
yTBCgVB60ZRxhS-ogRmY1a7uEakFItLSPJUG-fuHSgGCOwosZvD9YwZRo57GM8c
YhpFQAJqyjlgNs1LqK0858hZGnSPZrUYKoey-ORL3EKVVwKlLG1Jk5ggrTuxL-V
b0lt0CgYEA9k8rtM1WC6b7_JIPL7FqMS-YkK295GiRRyl9rkACmg7v4k25u416v
6kdXdakfVOETCp4oUnbqB4w9hvCcDS1M75rpae8rSuo8_rarDniT_fP4cow2NEQ
twjXGL6nfXrKY8A9w2pYPULyzsh2Bt6rpxdTw1oGZ_I5JMLB0qkpLncCgYBi2n_
eTvVd-UniRQPQhW6MaA9QOnRLHYC7lZUB6RAhfT0fr-Qa0Nqdxyt_r6g1gySCmC
TZh8oAIwLSUaHCkfNCfHzOyzDAXeXqGvSp7qQQBJQuiW6QTvW19FIbycQ0bTbWo
06xOnJFp7rjlHAeixsqTsMBMMHK9Hn7RxXDSyTDaQKBgQDXVFNzVufYe_1jyxT3
rvSVV3TbVujh3ADV45H6Wf9sS46vmx-6tW8QS3pe5R0ca30HUUHwTy93BB3tqks
L6ShYuipFwiSSh87GrRGq61fMbWsRi7-0bOFeAp55BYRLkKOLHS9hvYCy3eqDmI
CGdPg_tYcHC5b6HKqUVqc30acs9QKBgFJ-giLkideNXLjJG1xrgm3_Jy5vaOBdF
UktfZ9I5d6Xx3jxJhY0sHXuGxrw92yWYlekJ-WGbsPZdsnk-rjFYOs60g3qB8u3
6_gXaVNu3aBN6jAd2WYnURKhoaMatLo5vLCeczUU3XB6mPj81jnjJBhx56xG0oo
8I4L9OthSrdw9"""

TeamPublicKey = """MIIBCgKCAQEA7s5lRoIIN3Cn87dhQkcqlQLW6l9UoycB5samXtI-F5pp1ym0QWZ
C5JMX2m8wg_VjzCpe9KSv_3mtVOt8BD_NER_5cpnXamJRBpVSwk3rWyHjZmmBsP
YdJGJ1AiBtEhNGfYtL6Munxuskahc_DdXcFtFSFIYlFp-iPJs3TVk1wiovL5aee
df52Fm9NaMtcl8qmbKTxaFrbdIs0cxdHUjIuA1eqo4BQ1qcF8UsDR3iSQwioRwj
NEcEJKDxfWaA6IUYnbWz-5c2IgRqaY04a99i6cpf04wGhGHHc_kJSROvIrLx8uh
SWJVFU5N3jdtBgWgwb7-gzRy4Ty4MruGVbTLWuwIDAQAB"""