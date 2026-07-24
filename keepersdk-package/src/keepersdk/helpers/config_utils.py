from .. import crypto, utils
from ..errors import KeeperApiError
from ..proto import pam_pb2
from ..vault import nsf_management, vault_extensions, vault_online, vault_record


def pam_configuration_create_record_v6(
        vault: vault_online.VaultOnline,
        record: vault_record.TypedRecord,
        folder_uid: str) -> None:
    """Create a classic PAM configuration via pam/add_configuration_record."""
    if not record.record_uid:
        record.record_uid = utils.generate_uid()

    record_key = vault.vault_data.get_record_key(record.record_uid)
    if not record_key:
        record_key = utils.generate_aes_key()

    schema = vault.vault_data.get_record_type_by_name(record.record_type)
    record_data = vault_extensions.extract_typed_record_data(record, schema)
    json_data = vault_extensions.get_padded_json_bytes(record_data)

    car = pam_pb2.ConfigurationAddRequest()
    car.configurationUid = utils.base64_url_decode(record.record_uid)
    car.recordKey = crypto.encrypt_aes_v2(record_key, vault.keeper_auth.auth_context.data_key)
    car.data = crypto.encrypt_aes_v2(json_data, record_key)

    vault.keeper_auth.execute_auth_rest('pam/add_configuration_record', car)


def pam_configuration_create_record_nsf(
        vault: vault_online.VaultOnline,
        record: vault_record.TypedRecord,
        folder_uid: str) -> None:
    """Create a PAM configuration in an NSF folder via vault/records/v3/add_pam_configuration."""
    try:
        nsf_management.create_nsf_pam_configuration(
            vault, record, folder_uid, request_sync=True)
    except nsf_management.NsfError as exc:
        raise KeeperApiError('nsf_error', str(exc)) from exc


def create_pam_configuration_in_folder(
        vault: vault_online.VaultOnline,
        record: vault_record.TypedRecord,
        folder_uid: str) -> bool:
    """Create a v6 PAM configuration in *folder_uid* using NSF or classic placement.

    Returns True when the config was created as an NSF record (already placed in
    the folder). Returns False for classic configs, which still need a move into
    the shared folder after sync.
    """
    if vault.nsf_data is not None and nsf_management.is_nsf_folder(vault, folder_uid):
        pam_configuration_create_record_nsf(vault, record, folder_uid)
        return True

    pam_configuration_create_record_v6(vault, record, folder_uid)
    return False


def configuration_controller_get(vault: vault_online.VaultOnline, config_uid_bytes: bytes):
    """
    Get the Controller UID that has access to the configuration UID
    Retrieves a keeper.pam_controller record, from given configuration_uid provided in request.
    controller_uid is the UID of the user who has access to the configuration url_safe_str_to_bytes(config_uid)
    """
    rq = pam_pb2.PAMGenericUidRequest()
    rq.uid = config_uid_bytes

    config_info_rs = vault.keeper_auth.execute_auth_rest(
        'pam/get_configuration_controller', rq, response_type=pam_pb2.PAMController)

    if config_info_rs:
        return config_info_rs
    else:
        return None
