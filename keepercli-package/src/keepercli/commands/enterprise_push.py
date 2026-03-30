import argparse
import json
import os
import copy
import re
from typing import Any, List, Set, Dict, Optional

from . import base
from .. import api
from ..params import KeeperParams

from keepersdk import crypto, utils, generator
from keepersdk.proto import record_pb2
from keepersdk.enterprise import enterprise_types
from keepersdk.importer import keeper_format, import_utils
from keepersdk.vault import vault_extensions, vault_online
from keepersdk.authentication import keeper_auth
from keepersdk.vault.record_management import TypedRecord

logger = api.get_logger()


ENTERPRISE_PUSH_DESCRIPTION = """
"enterprise-push" command uses Keeper JSON record import format.
https://docs.keeper.io/secrets-manager/commander-cli/import-and-export-commands/json-import

To create template records use the Web Vault or any other Keeper client.
1. Create an empty folder for storing templates. e.g. "Templates"
2. Create records in that folder
3. export the folder as JSON
My Vault> export --format=json --folder=Templates templates.json
4. Optional: edit JSON file to delete the following properties:
   "uid", "schema", "folders" not used by "enterprise-push" command


The template JSON file should be either array of records or
an object that contains property "records" of array of records

Template record file examples:
1.   Array of records
[
    {
        "title": "Record For ${user_name}",
        "login": "${user_email}",
        "password": "${generate_password}",
        "login_url": "",
        "notes": "",
        "custom_fields": {
            "key1": "value1",
            "key2": "value2"
        }
    }
]

2. Object that holds "records" property
{
    "records": [
        {
            "title": "Record For ${user_name}",
        }
    ]
}


Supported template parameters:

    ${user_email}            User email address
    ${generate_password}     Generate random password
    ${user_name}             User name
"""


def load_template_records_from_file(file_path: str) -> list:
    """Load and validate template records from a JSON file.

    Accepts either a JSON array of records or an object with a "records" array.
    Raises CommandError if the file is missing, invalid, or contains no templates.
    """
    path = os.path.abspath(os.path.expanduser(file_path))
    if not os.path.isfile(path):
        raise base.CommandError(f"File {file_path} does not exist")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "records" in data:
        records = data["records"]
    elif isinstance(data, list):
        records = data
    else:
        records = None

    if not isinstance(records, list) or len(records) == 0:
        raise base.CommandError(f"File {file_path} does not contain record templates")

    return records


PARAMETER_PATTERN = re.compile(r"\${(\w+)}")
TRANSFER_RECORD_SUCCESS = "transfer_record_success"


def _substitute_value(value: str, values: Dict[str, str]) -> str:
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


def _substitute_in_dict(container: Dict, values: Dict[str, str]) -> None:
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


def _substitute_in_list(container: list, values: Dict[str, str]) -> List:
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


def _get_substitution_values(enterprise: enterprise_types.IEnterpriseData, email: str) -> Dict[str, str]:
    """Build substitution map for a user: user_email, user_name, generate_password."""
    values = {
        "user_email": email,
        "generate_password": generator.KeeperPasswordGenerator(length=32).generate(),
    }
    for u in enterprise.users.get_all_entities():
        if u.username.lower() == email.lower():
            values["user_name"] = u.full_name or ""
            break
    return values


def _substitute_record_params(
    enterprise: enterprise_types.IEnterpriseData, email: str, record_data: Dict
) -> None:
    """Fill template parameters in record_data for the given user (in place)."""
    values = _get_substitution_values(enterprise, email)
    _substitute_in_dict(record_data, values)


def _resolve_user_to_email(enterprise: enterprise_types.IEnterpriseData, user_id: str) -> Optional[str]:
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


def _resolve_team_to_uid(enterprise: enterprise_types.IEnterpriseData, team_id: str) -> Optional[str]:
    """Resolve team identifier (name or team_uid) to team_uid."""
    for t in enterprise.teams.get_all_entities() or []:
        if team_id == t.team_uid or team_id.lower() == t.name.lower():
            return t.team_uid
    return None


def _collect_recipient_emails(
    enterprise: enterprise_types.IEnterpriseData,
    current_username: str,
    user_ids: List[str],
    team_ids: List[str],
) -> Set[str]:
    """Resolve user_ids and team_ids to a set of recipient emails. Excludes current user."""
    emails = set()

    for user_id in user_ids or []:
        email = _resolve_user_to_email(enterprise, user_id)
        if email:
            if email.lower() != current_username.lower():
                emails.add(email)
        else:
            logger.warning("Cannot find user %s", user_id)

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
            logger.warning(
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
                    logger.warning("Cannot find team %s", team_id)

    return emails


def _build_typed_records_for_user(
    enterprise: enterprise_types.IEnterpriseData,
    email: str,
    record_data: List[Dict[str, Any]],
) -> List[TypedRecord]:
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
    vault: vault_online.VaultOnline,
    typed_records: List[TypedRecord],
    user_ec_key: Any,
    user_rsa_key: Any,
    record_keys_out: Dict[str, bytes],
) -> record_pb2.RecordsAddRequest:
    """Build RecordsAddRequest and fill record_keys_out with uid -> encrypted_key for transfer."""
    rq = record_pb2.RecordsAddRequest()
    for record in typed_records:
        add_record, uid, encrypted_key = _build_single_record_add(
            auth, vault, record, user_ec_key, user_rsa_key
        )
        record_keys_out[uid] = encrypted_key
        rq.records.append(add_record)
    return rq


def _build_single_record_add(
    auth: keeper_auth.KeeperAuth,
    vault: vault_online.VaultOnline,
    record: TypedRecord,
    user_ec_key: Any,
    user_rsa_key: Any,
) -> tuple[record_pb2.RecordAdd, str, bytes]:
    """Build one RecordAdd and return (add_record, record_uid, encrypted_record_key). Mutates record.uid and record.record_key."""
    record.uid = utils.generate_uid()
    record.record_key = utils.generate_aes_key()
    if user_ec_key:
        encrypted_record_key = crypto.encrypt_ec(record.record_key, user_ec_key)
    else:
        encrypted_record_key = crypto.encrypt_rsa(record.record_key, user_rsa_key)

    add_record = record_pb2.RecordAdd()
    add_record.record_uid = utils.base64_url_decode(record.uid)
    add_record.record_key = crypto.encrypt_aes_v2(record.record_key, auth.auth_context.data_key)
    add_record.client_modified_time = utils.current_milli_time()
    add_record.folder_type = record_pb2.user_folder

    data = vault_extensions.extract_typed_record_data(record, vault.vault_data.get_record_type_by_name(record.record_type))
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
    return add_record, record.uid, encrypted_record_key


def _add_transfer_and_cleanup(
    auth: keeper_auth.KeeperAuth,
    email: str,
    add_request: record_pb2.RecordsAddRequest,
    record_keys_for_user: Dict[str, Any],
) -> None:
    """Execute records_add, transfer ownership to user, then unlink from admin (pre_delete + delete)."""
    rs = auth.execute_auth_rest(
        "vault/records_add", add_request, response_type=record_pb2.RecordsModifyResponse
    )
    if not rs:
        raise ValueError("Failed to add records")
    pre_delete_objects = []
    transfer_rq = record_pb2.RecordsOnwershipTransferRequest()

    for rec in rs.records:
        if rec.status == record_pb2.RS_SUCCESS:
            record_uid = utils.base64_url_encode(rec.record_uid)
            pre_delete_objects.append({
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
            logger.warning(
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
    if not rs1:
        raise ValueError("Failed to transfer records")
    success_count = sum(
        1 for trec in rs1.transferRecordStatus if trec.status == TRANSFER_RECORD_SUCCESS
    )
    for trec in rs1.transferRecordStatus:
        if trec.status != TRANSFER_RECORD_SUCCESS:
            logger.warning("User: %s Transfer Record Error: (%s) %s", email, trec.status, trec.message)
    logger.info(
        'Pushed %d %s to "%s"',
        success_count,
        "record" if success_count == 1 else "records",
        email,
    )

    if not pre_delete_objects:
        return
    pre_delete_rq = {"command": "pre_delete", "objects": pre_delete_objects}
    pre_delete_rs = auth.execute_auth_command(pre_delete_rq)
    if not pre_delete_rs:
        raise ValueError("Failed to process delete records request")
    if pre_delete_rs.get("result") == "success":
        pdr = pre_delete_rs["pre_delete_response"]
        delete_rq = {"command": "delete", "pre_delete_token": pdr["pre_delete_token"]}
        auth.execute_auth_command(delete_rq)


def _process_one_recipient(
    enterprise: enterprise_types.IEnterpriseData,
    auth: keeper_auth.KeeperAuth,
    vault: vault_online.VaultOnline,
    email: str,
    record_data: List[Dict[str, Any]],
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
        logger.warning('User "%s" public key cannot be loaded. Skipping', email)
        return

    typed_records = _build_typed_records_for_user(enterprise, email, record_data)
    if not typed_records:
        return

    record_keys_for_user = {}
    add_request = _build_records_add_request(
        auth=auth,
        vault=vault,
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
        user_ids: List[str],
        team_ids: List[str],
        record_data: List[Dict[str, Any]],
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
                logger.warning('User "%s" public key cannot be loaded. Skipping', email)

        for email in emails:
            _process_one_recipient(
                enterprise=enterprise,
                auth=auth,
                vault=vault,
                email=email,
                record_data=record_data,
            )
            vault.sync_down()


class EnterprisePushCommand(base.ArgparseCommand):
    """CLI command: populate user vaults with template records (by user or team)."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog="enterprise-push",
            description="Populate user's vault with default records",
        )
        EnterprisePushCommand.add_arguments_to_parser(parser)
        super().__init__(parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--syntax-help",
            dest="syntax_help",
            action="store_true",
            help="Display help on file format and template parameters.",
        )
        parser.add_argument(
            "--team",
            dest="team",
            action="append",
            help="Team name or team UID. Records will be assigned to all users in the team.",
        )
        parser.add_argument(
            "--email",
            dest="user",
            action="append",
            help="User email or User ID. Records will be assigned to the user.",
        )
        parser.add_argument(
            "file",
            nargs="?",
            type=str,
            action="store",
            help="File name in JSON format that contains template records.",
        )

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if kwargs.get("syntax_help"):
            logger.info(ENTERPRISE_PUSH_DESCRIPTION)
            return

        base.require_login(context)
        base.require_enterprise_admin(context)

        file_arg = kwargs.get("file") or ""
        if not file_arg:
            raise base.CommandError("The template file name argument is required")

        template_records = load_template_records_from_file(file_arg)
        user_ids = kwargs.get("user") or []
        team_ids = kwargs.get("team") or []

        EnterprisePush.push_enterprise_records(
            context.enterprise_data,
            context.auth,
            context.vault,
            user_ids,
            team_ids,
            template_records,
        )
