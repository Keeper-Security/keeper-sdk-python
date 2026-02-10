"""Push template records to enterprise users (by user or team)."""

import json
import copy
import logging
import re
from typing import Any

from .. import crypto, utils, generator
from ..proto import record_pb2
from ..enterprise import enterprise_types
from ..importer import keeper_format, import_utils
from ..vault import vault_extensions, vault_online
from ..authentication import keeper_auth

PARAMETER_PATTERN = re.compile(r"\${(\w+)}")


def _substitute_value(value: str, values: dict[str, str]) -> str:
    """Replace all ${key} placeholders in a string with values from the given dict."""
    result = value
    while True:
        match = PARAMETER_PATTERN.search(result)
        if not match:
            break
        param = match.group(1)
        replacement = values.get(param) or param
        result = result[: match.start()] + replacement + result[match.end() :]
    return result


def _substitute_in_dict(container: dict, values: dict[str, str]) -> None:
    """Recursively substitute placeholders in dict (and nested dicts/lists) in place."""
    for key, val in list(container.items()):
        if isinstance(val, str):
            new_val = _substitute_value(val, values)
            if val != new_val:
                container[key] = new_val
        elif isinstance(val, dict):
            _substitute_in_dict(val, values)
        elif isinstance(val, list):
            container[key] = _substitute_in_list(val, values)


def _substitute_in_list(container: list, values: dict[str, str]) -> list:
    """Return a new list with placeholders substituted."""
    result = []
    for item in container:
        if isinstance(item, str):
            result.append(_substitute_value(item, values))
        elif isinstance(item, dict):
            _substitute_in_dict(item, values)
            result.append(item)
        elif isinstance(item, list):
            result.append(_substitute_in_list(item, values))
        else:
            result.append(item)
    return result


def _get_substitution_values(enterprise: enterprise_types.IEnterpriseData, email: str) -> dict[str, str]:
    """Build substitution map for a user: user_email, user_name, generate_password."""
    values = {
        "user_email": email,
        "generate_password": generator.generate(length=32),
    }
    for u in enterprise.users.get_all_entities():
        if u.username.lower() == email.lower():
            values["user_name"] = u.full_name or ""
            break
    return values


def _substitute_record_params(
    enterprise: enterprise_types.IEnterpriseData, email: str, record_data: dict
) -> None:
    """Fill template parameters in record_data for the given user (in place)."""
    values = _get_substitution_values(enterprise, email)
    _substitute_in_dict(record_data, values)


def _resolve_user_to_email(enterprise: enterprise_types.IEnterpriseData, user_id: str) -> str | None:
    """Resolve user identifier (email, name, or enterprise_user_id) to username (email)."""
    user_id_lower = user_id.lower()
    for u in enterprise.users.get_all_entities():
        if user_id_lower in (
            u.username.lower(),
            (u.full_name or "").lower(),
            str(u.enterprise_user_id),
        ):
            return u.username
    return None


def _resolve_team_to_uid(enterprise: enterprise_types.IEnterpriseData, team_id: str) -> str | None:
    """Resolve team identifier (name or team_uid) to team_uid."""
    for t in enterprise.teams.get_all_entities() or []:
        if team_id == t.team_uid or team_id.lower() == t.name.lower():
            return t.team_uid
    return None


def _collect_recipient_emails(
    enterprise: enterprise_types.IEnterpriseData,
    current_username: str,
    user_ids: list[str],
    team_ids: list[str],
) -> set[str]:
    """Resolve user_ids and team_ids to a set of recipient emails. Excludes current user."""
    emails = set()

    for user_id in user_ids or []:
        email = _resolve_user_to_email(enterprise, user_id)
        if email:
            if email.lower() != current_username.lower():
                emails.add(email)
        else:
            logging.warning("Cannot find user %s", user_id)

    if team_ids:
        users_map = {u.enterprise_user_id: u.username for u in enterprise.users.get_all_entities()}
        users_in_team = {}
        for tu in enterprise.team_users.get_all_links() or []:
            team_uid = tu.team_uid
            if team_uid not in users_in_team:
                users_in_team[team_uid] = []
            if tu.enterprise_user_id in users_map:
                users_in_team[team_uid].append(users_map[tu.enterprise_user_id])

        if not enterprise.teams.get_all_entities():
            logging.warning(
                "There are no teams to manage. Try to refresh your local data by syncing data from the server (use command `enterprise-down`)."
            )
        else:
            for team_id in team_ids:
                team_uid = _resolve_team_to_uid(enterprise, team_id)
                if team_uid and team_uid in users_in_team:
                    for member_email in users_in_team[team_uid]:
                        if member_email.lower() != current_username.lower():
                            emails.add(member_email)
                elif team_uid is None:
                    logging.warning("Cannot find team %s", team_id)

    return emails


def _build_typed_records_for_user(
    enterprise: enterprise_types.IEnterpriseData,
    email: str,
    record_data: list[dict[str, Any]],
) -> list:
    """Substitute template params and convert JSON templates to typed records."""
    user_records = []
    for template in record_data:
        record = copy.deepcopy(template)
        _substitute_record_params(enterprise, email, record)
        import_record = keeper_format.KeeperJsonMixin.json_to_record(record)
        if import_record:
            user_records.append(import_record)
    return [import_utils._as_typed_record(record=r) for r in user_records]


def _build_records_add_request(
    auth: keeper_auth.KeeperAuth,
    typed_records: list,
    user_ec_key: Any,
    user_rsa_key: Any,
    record_keys_out: dict[str, Any],
) -> record_pb2.RecordsAddRequest:
    """Build RecordsAddRequest and fill record_keys_out with uid -> encrypted_key for transfer."""
    rq = record_pb2.RecordsAddRequest()
    for record in typed_records:
        record.uid = utils.generate_uid()
        record.record_key = utils.generate_aes_key()
        if user_ec_key:
            encrypted_record_key = crypto.encrypt_ec(record.record_key, user_ec_key)
        else:
            encrypted_record_key = crypto.encrypt_rsa(record.record_key, user_rsa_key)
        record_keys_out[record.uid] = encrypted_record_key

        add_record = record_pb2.RecordAdd()
        add_record.record_uid = utils.base64_url_decode(record.uid)
        add_record.record_key = crypto.encrypt_aes_v2(record.record_key, auth.auth_context.data_key)
        add_record.client_modified_time = utils.current_milli_time()
        add_record.folder_type = record_pb2.user_folder

        data = vault_extensions.extract_typed_record_data(record)
        json_data = vault_extensions.get_padded_json_bytes(data)
        add_record.data = crypto.encrypt_aes_v2(json_data, record.record_key)

        if auth.auth_context.enterprise_ec_public_key:
            audit_data = vault_extensions.extract_audit_data(record)
            if audit_data:
                add_record.audit.version = 0
                add_record.audit.data = crypto.encrypt_ec(
                    json.dumps(audit_data).encode("utf-8"),
                    auth.auth_context.enterprise_ec_public_key,
                )
        rq.records.append(add_record)
    return rq


def _add_transfer_and_cleanup(
    auth: keeper_auth.KeeperAuth,
    email: str,
    add_request: record_pb2.RecordsAddRequest,
    record_keys_for_user: dict[str, Any],
) -> None:
    """Execute records_add, transfer ownership to user, then unlink from admin (pre_delete + delete)."""
    rs = auth.execute_auth_rest(
        "vault/records_add", add_request, response_type=record_pb2.RecordsModifyResponse
    )
    pre_delete_rq = {"command": "pre_delete", "objects": []}
    transfer_rq = record_pb2.RecordsOnwershipTransferRequest()

    for rec in rs.records:
        if rec.status == record_pb2.RS_SUCCESS:
            record_uid = utils.base64_url_encode(rec.record_uid)
            pre_delete_rq["objects"].append({
                "from_type": "user_folder",
                "delete_resolution": "unlink",
                "object_uid": record_uid,
                "object_type": "record",
            })
            record_key = record_keys_for_user[record_uid]
            tr = record_pb2.TransferRecord()
            tr.username = email
            tr.recordUid = rec.record_uid
            tr.recordKey = record_key
            tr.useEccKey = len(record_key) < 150
            transfer_rq.transferRecords.append(tr)
        else:
            logging.warning(
                "User: %s Create Record Error: (%s) %s",
                email,
                record_pb2.RecordModifyResult.Name(rec.status),
                rec.message,
            )

    if not transfer_rq.transferRecords:
        return

    rs1 = auth.execute_auth_rest(
        "vault/records_ownership_transfer",
        transfer_rq,
        response_type=record_pb2.RecordsOnwershipTransferResponse,
    )
    success_count = sum(
        1 for trec in rs1.transferRecordStatus if trec.status == "transfer_record_success"
    )
    for trec in rs1.transferRecordStatus:
        if trec.status != "transfer_record_success":
            logging.warning("User: %s Transfer Record Error: (%s) %s", email, trec.status, trec.message)
    logging.info(
        'Pushed %d %s to "%s"',
        success_count,
        "record" if success_count == 1 else "records",
        email,
    )

    if not pre_delete_rq["objects"]:
        return
    pre_delete_rs = auth.execute_auth_rest("vault/pre_delete", pre_delete_rq)
    if pre_delete_rs.get("result") == "success":
        pdr = pre_delete_rs["pre_delete_response"]
        delete_rq = {"command": "delete", "pre_delete_token": pdr["pre_delete_token"]}
        auth.execute_auth_rest("vault/delete", delete_rq)


def _process_one_recipient(
    enterprise: enterprise_types.IEnterpriseData,
    auth: keeper_auth.KeeperAuth,
    vault: vault_online.VaultOnline,
    email: str,
    record_data: list[dict[str, Any]],
) -> None:
    """Load user key, build records, add to vault, transfer ownership to user."""
    user_key = auth.get_user_keys(email)
    if user_key is None:
        return

    user_ec_key = None
    user_rsa_key = None
    if auth.auth_context.forbid_rsa and user_key.ec:
        user_ec_key = crypto.load_ec_public_key(user_key.ec)
    elif not auth.auth_context.forbid_rsa and user_key.rsa:
        user_rsa_key = crypto.load_rsa_public_key(user_key.rsa)
    if user_ec_key is None and user_rsa_key is None:
        logging.warning('User "%s" public key cannot be loaded. Skipping', email)
        return

    typed_records = _build_typed_records_for_user(enterprise, email, record_data)
    if not typed_records:
        return

    record_keys_for_user = {}
    add_request = _build_records_add_request(
        auth=auth,
        typed_records=typed_records,
        user_ec_key=user_ec_key,
        user_rsa_key=user_rsa_key,
        record_keys_out=record_keys_for_user,
    )

    if not add_request.records:
        return

    _add_transfer_and_cleanup(
        auth=auth,
        email=email,
        add_request=add_request,
        record_keys_for_user=record_keys_for_user,
    )


class EnterprisePush:
    """Pushes record templates to specified users or team members."""

    @staticmethod
    def push_enterprise_records(
        enterprise: enterprise_types.IEnterpriseData,
        auth: keeper_auth.KeeperAuth,
        vault: vault_online.VaultOnline,
        user_ids: list[str],
        team_ids: list[str],
        record_data: list[dict[str, Any]],
    ) -> None:
        """Resolve recipients, then for each user substitute template params and add/transfer records."""
        emails = list(
            _collect_recipient_emails(
                enterprise,
                auth.auth_context.username,
                user_ids or [],
                team_ids or [],
            )
        )
        if not emails:
            raise ValueError("No users")

        no_key_emails = auth.load_user_public_keys(emails, False)
        if isinstance(no_key_emails, list):
            for email in no_key_emails:
                logging.warning('User "%s" public key cannot be loaded. Skipping', email)

        for email in emails:
            _process_one_recipient(
                enterprise=enterprise,
                auth=auth,
                vault=vault,
                email=email,
                record_data=record_data,
            )
            vault.sync_down()
