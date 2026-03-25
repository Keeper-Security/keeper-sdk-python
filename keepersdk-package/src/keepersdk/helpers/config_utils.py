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


def configuration_controller_get(vault: vault_online.VaultOnline, config_uid_bytes: bytes):
    """
    Get the Controller UID that has access to the configuration UID
    Retrieves a keeper.pam_controller record, from given configuration_uid provided in request.
    controller_uid is the UID of the user who has access to the configuration url_safe_str_to_bytes(config_uid)
    """
    rq = pam_pb2.PAMGenericUidRequest()
    rq.uid = config_uid_bytes

    config_info_rs = vault.keeper_auth.execute_auth_rest('pam/get_configuration_controller', rq, response_type=pam_pb2.PAMController)

    if config_info_rs:
        return config_info_rs
    else:
        return None
