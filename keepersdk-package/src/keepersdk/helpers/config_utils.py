from ..proto import pam_pb2
from ..vault import vault_extensions, vault_online, vault_record
from .. import utils, crypto

def pam_configuration_create_record_v6(vault: vault_online.VaultOnline, record: vault_record.TypedRecord, folder_uid: str):
    if not record.record_uid:
        record.record_uid = utils.generate_uid()

    if not record.record_key:
        record.record_key = utils.generate_aes_key()

    record_data = vault_extensions.extract_typed_record_data(record)
    json_data = record.load_record_data(record_data)

    car = pam_pb2.ConfigurationAddRequest()
    car.configurationUid = utils.base64_url_decode(record.record_uid)
    car.recordKey = crypto.encrypt_aes_v2(record.record_key, vault.keeper_auth.auth_context.data_key)
    car.data = crypto.encrypt_aes_v2(json_data, record.record_key)

    vault.keeper_auth.execute_auth_rest('pam/add_configuration_record', car)
