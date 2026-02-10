import argparse
import os
import json
import copy
import logging
import re

from keepersdk import crypto, utils, generator
from keepersdk.proto import record_pb2
from keepersdk.enterprise import enterprise_types
from keepersdk.importer import keeper_format, import_utils
from keepersdk.vault import vault_extensions

from . import base
from .. import api
from ..params import KeeperParams

logger = api.get_logger()


enterprise_push_description = '''
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

'''
parameter_pattern = re.compile(r'\${(\w+)}')


class EnterprisePushCommand(base.ArgparseCommand):

    def __init__(self):
        parser = argparse.ArgumentParser(prog='enterprise-push', description='Populate user\'s vault with default records')
        EnterprisePushCommand.add_arguments_to_parser(parser)
        super().__init__(parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='Display help on file format and template parameters.')
        parser.add_argument('--team', dest='team', action='append', help='Team name or team UID. Records will be assigned to all users in the team.')
        parser.add_argument('--email', dest='user', action='append', help='User email or User ID. Records will be assigned to the user.')
        parser.add_argument('file', nargs='?', type=str, action='store', help='File name in JSON format that contains template records.')


    @staticmethod
    def substitute_field_params(field, values):
        global parameter_pattern
        value = field
        while True:
            m = parameter_pattern.search(value)
            if not m:
                break
            p = m.group(1)
            pv = values.get(p) or p
            value = value[:m.start()] + pv + value[m.end():]
        return value

    @staticmethod
    def enumerate_and_substitute_list_values(container, values):

        result = []
        for p in container:
            if type(p) == str:
                value = EnterprisePushCommand.substitute_field_params(p, values)
                result.append(value)
            elif type(p) == dict:
                EnterprisePushCommand.enumerate_and_substitute_dict_fields(p, values)
                result.append(p)
            elif type(p) == list:
                result.append(EnterprisePushCommand.enumerate_and_substitute_list_values(p, values))
            else:
                result.append(p)
        return result

    @staticmethod
    def enumerate_and_substitute_dict_fields(container, values):

        for p in container.items():
            if type(p[1]) == str:
                value = EnterprisePushCommand.substitute_field_params(p[1], values)
                if p[1] != value:
                    container[p[0]] = value
            elif type(p[1]) == dict:
                EnterprisePushCommand.enumerate_and_substitute_dict_fields(p[1], values)
            elif type(p[1]) == list:
                container[p[0]] = EnterprisePushCommand.enumerate_and_substitute_list_values(p[1], values)

    @staticmethod
    def substitute_record_params(enterprise: enterprise_types.IEnterpriseData, email, record_data):

        values = {
            'user_email': email,
            'generate_password': generator.generate(length=32)
        }
        for u in enterprise.users.get_all_entities():
            if u.username.lower() == email.lower():
                values['user_name'] = u.full_name or ''
                break

        EnterprisePushCommand.enumerate_and_substitute_dict_fields(record_data, values)

    def execute(self, context: KeeperParams, **kwargs):
        if kwargs.get('syntax_help'):
            logging.info(enterprise_push_description)
            return
        
        base.require_login(context)
        base.require_enterprise_admin(context)

        vault = context.vault
        auth = context.auth
        enterprise = context.enterprise_data

        name = kwargs.get('file') or ''
        if not name:
            raise base.CommandError('The template file name arguments are required')

        file_name = os.path.abspath(os.path.expanduser(name))
        if os.path.isfile(file_name):
            with open(file_name, 'r', encoding='utf-8') as f:
                template_records = json.load(f)
        else:
            raise base.CommandError(f'File {name} does not exists')
        if isinstance(template_records, dict):
            if 'records' in template_records:
                template_records = template_records['records']

        if not isinstance(template_records, list) or len(template_records) == 0:
            raise base.CommandError(f'File {name} does not contain record templates')

        user_ids = kwargs.get('user')
        team_ids = kwargs.get('team')
        emails = list(EnterprisePushCommand.collect_emails(enterprise, auth.auth_context.username, user_ids, team_ids))

        if len(emails) == 0:
            raise base.CommandError('No users')

        no_key_emails = auth.load_user_public_keys(emails, False)
        if isinstance(no_key_emails, list):
            for email in no_key_emails:
                logging.warning('User \"%s\" public key cannot be loaded. Skipping', email)

        record_keys = {}

        for email in emails:
            user_key = auth.get_user_keys(email)
            if user_key is None:
                continue
            user_ec_key = None
            user_rsa_key = None
            if auth.auth_context.forbid_rsa and user_key.ec:
                user_ec_key = crypto.load_ec_public_key(user_key.ec)
            elif not auth.auth_context.forbid_rsa and user_key.rsa:
                user_rsa_key = crypto.load_rsa_public_key(user_key.rsa)
            if user_ec_key is None and user_rsa_key is None:
                logging.warning('User \"%s\" public key cannot be loaded. Skipping', email)
                continue

            user_records = []
            for r in template_records:
                record = copy.deepcopy(r)
                EnterprisePushCommand.substitute_record_params(enterprise, email, record)
                import_record = keeper_format.KeeperJsonMixin.json_to_record(record)
                if import_record:
                    user_records.append(import_record)

            typed_records = []
            for user_record in user_records:
                typed_record = import_utils._as_typed_record(record=user_record)
                typed_records.append(typed_record)

            record_keys[email] = {}
            rq = record_pb2.RecordsAddRequest()

            for record in typed_records:
                record.uid = utils.generate_uid()
                record.record_key = utils.generate_aes_key()
                if user_ec_key:
                    encrypted_record_key = crypto.encrypt_ec(record.record_key, user_ec_key)
                else:
                    encrypted_record_key = crypto.encrypt_rsa(record.record_key, user_rsa_key)
                record_keys[email][record.uid] = encrypted_record_key

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
                            json.dumps(audit_data).encode('utf-8'), auth.auth_context.enterprise_ec_public_key)
                rq.records.append(add_record)

            if len(rq.records) > 0:
                rs = auth.execute_auth_rest('vault/records_add', rq, response_type=record_pb2.RecordsModifyResponse)
                pre_delete_rq = {
                    'command': 'pre_delete',
                    'objects': []
                }
                rq1 = record_pb2.RecordsOnwershipTransferRequest()
                for rec in rs.records:
                    if rec.status == record_pb2.RS_SUCCESS:
                        record_uid = utils.base64_url_encode(rec.record_uid)
                        pre_delete_rq['objects'].append({
                            'from_type': 'user_folder',
                            'delete_resolution': 'unlink',
                            'object_uid': record_uid,
                            'object_type': 'record'
                        })
                        record_key = record_keys[email][record_uid]
                        tr = record_pb2.TransferRecord()
                        tr.username = email
                        tr.recordUid = rec.record_uid
                        tr.recordKey = record_key
                        tr.useEccKey = len(record_key) < 150
                        rq1.transferRecords.append(tr)
                    else:
                        logging.warning('User: %s Create Record Error: (%s) %s', email, record_pb2.RecordModifyResult.Name(rec.status), rec.message)

                if len(rq1.transferRecords) > 0:
                    record_no = 0
                    rs1 = auth.execute_auth_rest('vault/records_ownership_transfer', rq1, response_type=record_pb2.RecordsOnwershipTransferResponse)
                    for trec in rs1.transferRecordStatus:
                        if trec.status == 'transfer_record_success':
                            record_no += 1
                        else:
                            logging.warning('User: %s Transfer Record Error: (%s) %s', email, trec.status, trec.message)
                    logging.info('Pushed %d %s to "%s"', record_no, 'record' if record_no == 1 else 'records', email)

                if len(pre_delete_rq['objects']) > 0:
                    pre_delete_rs = auth.execute_auth_rest('vault/pre_delete', pre_delete_rq)
                    if pre_delete_rs['result'] == 'success':
                        pdr = pre_delete_rs['pre_delete_response']
                        delete_rq = {
                            'command': 'delete',
                            'pre_delete_token': pdr['pre_delete_token']
                        }
                        auth.execute_auth_rest('vault/delete', delete_rq)
            vault.sync_down()

    @staticmethod
    def collect_emails(enterprise: enterprise_types.IEnterpriseData, username: str, user_ids: list[str], team_ids: list[str]):
        # Collect emails from individual users and from teams
        emails = set()

        for user in user_ids:
            user_email = None
            for u in enterprise.users.get_all_entities():
                if user.lower() in [u.username.lower(), (u.full_name or '').lower(), str(u.enterprise_user_id)]:
                    user_email = u.username
                    break
            if user_email:
                if user_email.lower() != username.lower():
                    emails.add(user_email)
            else:
                logging.warning('Cannot find user %s', user)

        if team_ids:
            users_map = {}
            for u in enterprise.users.get_all_entities():
                users_map[u.enterprise_user_id] = u.username
            users_in_team = {}

            if enterprise.team_users.get_all_links():
                for tu in enterprise.team_users.get_all_links():
                    team_uid = tu.team_uid
                    if team_uid not in users_in_team:
                        users_in_team[team_uid] = []
                    if tu.enterprise_user_id in users_map:
                        users_in_team[team_uid].append(users_map[tu.enterprise_user_id])

            if enterprise.teams.get_all_entities():
                for team in team_ids:
                    team_uid = None
                    if team in enterprise.teams.get_all_entities():
                        team_uid = team_uid
                    else:
                        for t in enterprise.teams.get_all_entities():
                            if team.lower() == t.name.lower():
                                team_uid = t.team_uid
                    if team_uid:
                        if team_uid in users_in_team:
                            for user_email in users_in_team[team_uid]:
                                if user_email.lower() != username.lower():
                                    emails.add(user_email)
                    else:
                        logging.warning('Cannot find team %s', team)
            else:
                logging.warning('There are no teams to manage. Try to refresh your local data by syncing data from the server (use command `enterprise-down`).')

        return emails
