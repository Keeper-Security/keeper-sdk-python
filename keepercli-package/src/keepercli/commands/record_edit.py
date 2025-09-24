import argparse
import base64
import collections
import dataclasses
import datetime
import itertools
import json
import os
import re
from typing import Iterable, Optional, List, Any, Sequence, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from colorama import Fore, Back, Style

from keepersdk.proto import record_pb2
from keepersdk.vault import (record_types, typed_field_utils, vault_record, attachment, record_facades,
                             record_management, vault_online, vault_data, vault_types, vault_utils, vault_extensions)
from keepersdk import crypto, generator, utils

from . import base, enterprise_utils
from .. import prompt_utils, api, constants
from ..helpers import folder_utils, record_utils, report_utils, share_utils, timeout_utils
from ..params import KeeperParams


logger = api.get_logger()


@dataclasses.dataclass(frozen=True)
class ParsedFieldValue:
    section: str
    type: str
    label: str
    value: str


record_fields_description = '''
Commander supports two types of records:
1. Typed
2. Legacy

To create a Legacy record type pass "legacy" or "general" record type parameter 

The content of Typed record is defined by schema. The schema name is stored on record "type" field
To view all available record types:  "record-type-info" or "rti" 
To view fields for particular record type:  "record-type-info --list-record <record type>"  "rti -lt login"
To view field information type: "record-type-info --list-field <field type>"  "rti -lf host"

The Commander supports the following syntax for record fields:
[<FIELD_SET>][<FIELD_TYPE>][<FIELD_LABEL>]=[FIELD_VALUE]
Field components are separated with a dot (.)
1. FIELD_SET: Optional. 'f' or 'c'. Field section: field/f or custom/c
2. FIELD_TYPE: Mandatory for main fields optional for custom. if omitted 'text' field type is assumed
3. FIELD_LABEL: Optional. When adding multiple custom fields of the same type make sure the label is unique.
4. FIELD_VALUE: Optional. If is empty them field to be deleted. The field value content depends on field type.
Example:   "url.Web URL=https://google.com"

Field types are case sensitive
Field labels are case insensitive

Use full <FIELD_TYPE>.<FIELD_LABEL> syntax when field label collides with field type. 
Example:  "password"          "password" field with no label
          "text.password"     "text" field with "password" label
          "Password"          "text" field with "Password" label`

Use full <FIELD_TYPE>.<FIELD_LABEL> syntax when field label contains a dot (.)
Example:   "google.com"       Incorrect field type google
           "text.google.com"  Field type "text" field label "google.com"

If field label contains equal sign '=' then double it. 
If field value starts with equal sign then prepend a value with space
Example:
    text.aaa==bbb=" =ccc"     sets custom field with label "aaa=bbb" to "=ccc"        

The Legacy records define the following field types.  
1. login
2. password
3. url
4. oneTimeCode

All records support:
3. Custom Fields: Any field that is not the pre-defined field is added to custom field section. 
   "url.Web URL=https://google.com"
4. File Attachments:   "file=@<FILE_NAME>"

Supported record type field values:
Field Type        Description            Value Type     Examples
===========       ==================     =========+     =====================================
file              File attachment                       @file.txt
date              Unix epoch time.       integer        1668639533 | 2022-11-16T10:58:53Z | 2022-11-16
host              host name / port       object         {"hostName": "", "port": ""} 
                                                        192.168.1.2:4321
address           Address                object         {"street1": "", "street2": "", "city": "", "state": "", 
                                                         "zip": "", "country": ""}
                                                        123 Main St, SmallTown, CA 12345, USA
phone             Phone                  object         {"region": "", "number": "", "ext": "", "type": ""}
                                                        Mobile: US (555)555-1234
name              Person name            object         {"first": "", "middle": "", "last": ""}
                                                        Doe, John Jr. | Jane Doe
securityQuestion  Security Q & A         array of       [{"question": "", "answer": ""}]
                                         objects        What city you were ...? city; What is the name of ...? name
paymentCard       Payment Card           object         {"cardNumber": "", "cardExpirationDate": "", "cardSecurityCode": ""}
                                                        4111111111111111 04/2026 123
bankAccount       Bank Account           object         {"accountType": "", "routingNumber": "", "accountNumber": ""}
                                                        Checking: 123456789 987654321
keyPair           Key Pair               object         {"publicKey": "", "privateKey": ""}

oneTimeCode       TOTP URL               string         otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&issuer=Keeper
note              Masked multiline text  string         
multiline         Multiline text         string         
secret            Masked text            string         
login             Login                  string                                         
email             Email                  string         'name@company.com'                                
password          Password               string         
url               URL                    string         https://google.com/
text              Free form text         string         This field type generally has a label

$<ACTION>[:<PARAMS>, <PARAMS>]   executes an action that returns a field value   

Value                   Field type         Description                      Example
====================    ===============    ===================              ==============
$GEN:[alg],[n]          password           Generates a random password      $GEN:dice,5
                                           Default algorith is rand         alg: [rand | dice | crypto]
                                           Optional: password length        
$GEN                    oneTimeCode        Generates TOTP URL               
$GEN:[alg,][enc]        keyPair            Generates a key pair and         $GEN:ec,enc
                                           optional passcode                alg: [rsa | ec | ed25519], enc 
$JSON:<JSON TEXT>       any object         Sets a field value as JSON       
                                           phone.Cell=$JSON:'{"number": "(555) 555-1234", "type": "Mobile"}' 
'''

class RecordEditMixin(typed_field_utils.TypedFieldMixin):
    def __init__(self) -> None:
        self.warnings: List[str] = []

    def on_warning(self, message: str) -> None:
        if message:
            self.warnings.append(message)

    def on_info(self, message):
        logger.info(message)

    @staticmethod
    def parse_field(field: str) -> ParsedFieldValue:
        if not isinstance(field, str):
            raise ValueError('Incorrect field value')

        name, sel, value = field.partition('=')
        if not sel:
            raise ValueError(f'Expected: <field>=<value>, got: {field}; Missing `=`')
        if not name:
            raise ValueError(f'Expected: <field>=<value>, got: {field}; Missing <field>')
        while value.startswith('='):
            name1, sel, value1 = value[1:].partition('=')
            if sel:
                name += sel + name1
                value = value1
            else:
                break

        field_section = ''
        if name.startswith('f.') or name.startswith('c.'):
            field_section = name[0]
            name = name[2:]
        if not name:
            raise ValueError(f'Expected: <field>=<value>, got: {field}; Missing field type or label')

        field_type, sep, field_label = name.partition('.')
        if not sep:
            if field_type in ('file',):
                pass
            elif field_type not in record_types.RecordFields:
                field_label = field_type
                field_type = ''
        return ParsedFieldValue(field_section, field_type, field_label, value.strip())

    def assign_legacy_fields(self, record: vault_record.PasswordRecord, fields: List[ParsedFieldValue]) -> None:
        if not isinstance(record, vault_record.PasswordRecord):
            raise ValueError('Expected legacy record')
        if not isinstance(fields, list):
            raise ValueError('Fields parameter: expected array of strings')

        action_params: List[str] = []
        for parsed_field in fields:
            if parsed_field.type == 'login':
                record.login = parsed_field.value
            elif parsed_field.type == 'password':
                if self.is_generate_value(parsed_field.value, action_params):
                    record.password = self.generate_password(action_params)
                else:
                    record.password = parsed_field.value
            elif parsed_field.type == 'url':
                record.link = parsed_field.value
            elif parsed_field.type == 'oneTimeCode':
                if self.is_generate_value(parsed_field.value, action_params):
                    record.totp = self.generate_totp_url()
                else:
                    record.totp = parsed_field.value
            else:
                field_type = parsed_field.type
                field_label = parsed_field.label
                if field_type and not field_label:
                    field_label = field_type
                index = next((i for i, x in enumerate(record.custom) if x.name.lower() == field_label.lower()), -1)
                if parsed_field.value:
                    if 0 <= index < len(record.custom):
                        record.custom[index].value = parsed_field.value
                    else:
                        record.custom.append(vault_record.CustomField.create_field(field_label, parsed_field.value))
                else:
                    if 0 <= index < len(record.custom):
                        record.custom.pop(index)

    def is_json_value(self, value: str, parameters: List[Any]) -> Optional[bool]:
        if value.startswith('$JSON'):
            value = value[5:]
            if value.startswith(':'):
                j_str = value[1:]
                if j_str and isinstance(parameters, list):
                    try:
                        parameters.append(json.loads(j_str))
                    except Exception as e:
                        self.on_warning(f'Invalid JSON value: {j_str}: {e}')
            return True

    @staticmethod
    def is_generate_value(value: str, parameters: List[str]) -> Optional[bool]:
        if value.startswith("$GEN"):
            value = value[4:]
            if value.startswith(':'):
                gen_parameters = value[1:]
                if gen_parameters and isinstance(parameters, list):
                    parameters.extend((x.strip() for x in gen_parameters.split(',')))
            return True

    @staticmethod
    def generate_key_pair(key_type: str, passphrase: str) -> dict:
        private_key: Any
        public_key: Any
        if key_type == 'ec':
            private_key, public_key = crypto.generate_ec_key()
        elif key_type == 'ed25519':
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
        else:
            private_key, public_key = crypto.generate_rsa_key()
        encryption = serialization.BestAvailableEncryption(passphrase.encode()) \
            if passphrase else serialization.NoEncryption()

        # noinspection PyTypeChecker
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption)
        # noinspection PyTypeChecker
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return {
            'privateKey': pem_private_key.decode(),
            'publicKey': pem_public_key.decode(),
        }

    @staticmethod
    def generate_password(parameters: Optional[Sequence[str]]=None) -> str:
        if isinstance(parameters, (tuple, list, set)):
            algorithm = next((x for x in parameters if x in ('rand', 'dice', 'crypto')), 'rand')
            length = next((x for x in parameters if x.isnumeric()), None)
            if isinstance(length, str) and len(length) > 0:
                try:
                    length = int(length)
                except ValueError:
                    pass
        else:
            algorithm = 'rand'
            length = None

        gen: generator.PasswordGenerator
        if algorithm == 'crypto':
            gen = generator.CryptoPassphraseGenerator()
        elif algorithm == 'dice':
            if isinstance(length, int):
                if length < 1:
                    length = 1
                elif length > 40:
                    length = 40
            else:
                length = 5
            gen = generator.DicewarePasswordGenerator(length)
        else:
            if isinstance(length, int):
                if length < 4:
                    length = 4
                elif length > 200:
                    length = 200
            else:
                length = 20
            gen = generator.KeeperPasswordGenerator(length=length)
        return gen.generate()

    @staticmethod
    def generate_totp_url() -> str:
        secret = base64.b32encode(crypto.get_random_bytes(20)).decode()
        return f'otpauth://totp/Commander?secret={secret}&issuer=Keeper'

    def validate_json_value(self, field_type: str, field_value: Any) -> Any:
        record_field = record_types.RecordFields.get(field_type)
        if not record_field:
            return field_value
        value_type = record_types.FieldTypes[record_field.type]
        if isinstance(value_type.value, dict):
            f_fields = set(value_type.value.keys())
            if isinstance(field_value, (list, dict)):
                if isinstance(field_value, list):
                    if record_field.multiple != record_types.Multiple.Always:
                        self.on_warning(f'Field \"{record_field.name}\" does not support multiple values')
                d_rs = []
                for dv in field_value if isinstance(field_value, list) else [field_value]:
                    if isinstance(dv, dict):
                        v_fields = set(dv.keys())
                        v_fields.difference_update(f_fields)
                        if len(v_fields) > 0:
                            self.on_warning(f'Field \"{record_field.name}\": '
                                            f'Properties \"{", ".join(v_fields)}\" are not supported.')
                        for key in f_fields:
                            if key not in dv:
                                dv[key] = ''
                        d_rs.append(dv)
                    else:
                        self.on_warning(f'Field \"{record_field.name}\": Incorrect value: \"{json.dumps(dv)}\"')
                        return
                if len(d_rs) > 1:
                    return d_rs
                elif len(d_rs) == 1:
                    return d_rs[0]
            else:
                self.on_warning(f'Field \"{record_field.name}\" ')
        elif isinstance(field_value, type(value_type.value)):
            return field_value
        else:
            self.on_warning(f'Field \"{record_field.name}\": Incorrect value: \"{field_value}\" ')

    @staticmethod
    def validate_notes(notes: str) -> str:
        if isinstance(notes, str):
            notes = notes.replace('\\n', '\n')
        return notes

    @staticmethod
    def adjust_typed_record_fields(record: vault_record.TypedRecord, typed_fields: List[vault_types.RecordTypeField]) -> Optional[bool]:
        new_fields = []
        old_fields = [x for x in itertools.chain(record.fields, record.custom) if x.value]
        should_rebuild = False
        for typed_field in typed_fields:
            field_type = typed_field.type
            if not field_type:
                return None
            field_label = typed_field.label or ''
            required = typed_field.required
            rf = record_types.RecordFields.get(field_type)
            ignore_label = rf.multiple == record_types.Multiple.Never if rf else False

            # exact match
            field = next((x for x in old_fields if x.type == field_type and
                          (ignore_label or (x.label or '') == field_label)), None)
            # match first not empty
            if not field:
                if field_label:
                    field = next((x for x in old_fields if x.type == field_type and not x.label and x.value), None)
                else:
                    field = next((x for x in old_fields if x.type == field_type and x.value), None)

            if field:
                old_fields.remove(field)
                new_fields.append(field)
                field.required = required
                if field.label != field_label:
                    field.label = field_label
                    should_rebuild = True
                continue

            field = vault_record.TypedField.create_field(field_type, field_label)
            field.required = required
            new_fields.append(field)
            should_rebuild = True

        custom = []
        if len(old_fields) > 0:
            custom.extend(old_fields)
            should_rebuild = True

        if should_rebuild:
            record.fields.clear()
            record.fields.extend(new_fields)
            record.custom.clear()
            record.custom.extend((x for x in custom if x.value))

        return should_rebuild

    def assign_typed_fields(self, record: vault_record.TypedRecord, fields: List[ParsedFieldValue]) -> None:
        if not isinstance(record, vault_record.TypedRecord):
            raise ValueError('Expected typed record')
        if not isinstance(fields, list):
            raise ValueError('Fields parameter: expected array of fields')

        parsed_fields = collections.deque(fields)
        while len(parsed_fields) > 0:
            parsed_field = parsed_fields.popleft()
            field_type = parsed_field.type or 'text'
            field_label = parsed_field.label or ''
            skip_validation = not parsed_field.value or parsed_field.value.startswith('$JSON')
            if field_type not in record_types.RecordFields:
                if not skip_validation:
                    self.on_warning(f'Field type \"{field_type}\" is not supported. Field: {field_type}.{field_label}')
                    continue
            rf = record_types.RecordFields.get(field_type)
            ignore_label = rf.multiple == record_types.Multiple.Never if rf else False

            record_field: Optional[vault_record.TypedField] = None
            is_field = False
            if parsed_field.section == 'f':   # ignore label
                fs = [x for x in record.fields if x.type == field_type and isinstance(x, vault_record.TypedField)]
                if len(fs) == 0:
                    self.on_warning(f'Field type \"{field_type}\" is not found for record type {record.record_type}')
                elif len(fs) == 1:
                    record_field = fs[0]
                else:
                    fs = [x for x in fs if (x.label or '').lower() == field_label.lower()]
                    if len(fs) == 0:
                        self.on_warning(
                            f'Field type \"{field_type}\" is not found for record type {record.record_type}')
                    else:
                        record_field = fs[0]
                is_field = True
            else:
                f_label = field_label.lower()
                record_field = next(
                    (x for x in record.fields
                     if (not parsed_field.type or x.type == parsed_field.type) and
                     (ignore_label or (x.label or '').lower() == f_label)), None)
                if record_field:
                    is_field = True
                else:
                    record_field = next(
                        (x for x in record.custom
                         if (not parsed_field.type or x.type == parsed_field.type) and
                         (ignore_label or (x.label or '').lower() == f_label)), None)
                    if record_field is None:
                        if not parsed_field.value:
                            continue
                        record_field = vault_record.TypedField.create_field(field_type or 'text', field_label)
                        record.custom.append(record_field)
            if not record_field:
                continue

            if isinstance(parsed_field.value, str) and parsed_field.value:
                action_params: List[str] = []
                value: Any = None
                if self.is_generate_value(parsed_field.value, action_params):
                    if record_field.type == 'password':
                        value = self.generate_password(action_params)
                    elif record_field.type in ('oneTimeCode', 'otp'):
                        value = self.generate_totp_url()
                    elif record_field.type in ('keyPair', 'privateKey'):
                        should_encrypt = 'enc' in action_params
                        passphrase = self.generate_password() if should_encrypt else ''
                        key_type = next((x for x in action_params if x in ('rsa', 'ec', 'ed25519')), 'rsa')
                        value = self.generate_key_pair(key_type, passphrase)
                        if passphrase:
                            parsed_fields.append(ParsedFieldValue('', 'password', 'passphrase', passphrase))
                    else:
                        self.on_warning(f'Cannot generate a value for a \"{record_field.type}\" field.')
                elif self.is_json_value(parsed_field.value, action_params):
                    if len(action_params) > 0:
                        value = self.validate_json_value(record_field.type, action_params[0])
                else:
                    rf = record_types.RecordFields[record_field.type]
                    ft = record_types.FieldTypes.get(rf.type)
                    if ft is None:
                        self.on_warning(f'Unsupported field type: {rf.type}')
                    else:
                        if isinstance(ft.value, str):
                            value = parsed_field.value
                            if ft.name == 'multiline':
                                value = self.validate_notes(value)
                        elif isinstance(ft.value, int):
                            if parsed_field.value.isdigit():
                                value = int(parsed_field.value)
                                if value < 1_000_000_000:
                                    value *= 1000
                            else:
                                if len(parsed_field.value) <= 10:
                                    dt = datetime.datetime.strptime(parsed_field.value, '%Y-%m-%d')
                                else:
                                    dt = datetime.datetime.strptime(parsed_field.value, '%Y-%m-%dT%H:%M:%SZ')
                                value = int(dt.timestamp() * 1000)
                        elif isinstance(ft.value, bool):
                            lv = parsed_field.value.lower()
                            if lv in ('1', 'y', 'yes', 't', 'true'):
                                value = True
                            elif lv in ('0', 'n', 'no', 'f', 'false'):
                                value = False
                            else:
                                self.on_warning(f'Incorrect boolean value \"{parsed_field.value}\": [t]rue or [f]alse')
                        elif isinstance(ft.value, dict):
                            if ft.name == 'name':
                                value = RecordEditMixin.import_name_field(parsed_field.value)
                            elif ft.name == 'address':
                                value = RecordEditMixin.import_address_field(parsed_field.value)
                            elif ft.name == 'host':
                                value = RecordEditMixin.import_host_field(parsed_field.value)
                            elif ft.name == 'phone':
                                value = RecordEditMixin.import_phone_field(parsed_field.value)
                            elif ft.name == 'paymentCard':
                                value = RecordEditMixin.import_card_field(parsed_field.value)
                            elif ft.name == 'bankAccount':
                                value = RecordEditMixin.import_account_field(parsed_field.value)
                            elif ft.name == 'securityQuestion':
                                value = []
                                for qa in parsed_field.value.split(';'):
                                    qa = qa.strip()
                                    qav = RecordEditMixin.import_q_and_a_field(qa)
                                    if qav:
                                        value.append(qav)
                            elif ft.name == 'privateKey':
                                value = RecordEditMixin.import_ssh_key_field(parsed_field.value)
                            elif ft.name == 'schedule':
                                value = RecordEditMixin.import_schedule_field(parsed_field.value)
                            else:
                                self.on_warning(f'Unsupported field type: {record_field.type}')
                if value:
                    if isinstance(value, list):
                        record_field.value.clear()
                        record_field.value.extend(value)
                    else:
                        if len(record_field.value) == 0:
                            record_field.value.append(value)
                        else:
                            if isinstance(value, dict) and isinstance(record_field.value[0], dict):
                                record_field.value[0].update(value)
                            else:
                                record_field.value[0] = value
            else:
                if is_field:
                    record_field.value.clear()
                else:
                    index = next((i for i, x in enumerate(record.custom) if x is record_field), -1)
                    if 0 <= index < len(record.custom):
                        record.custom.pop(index)

    def upload_attachments(self, vault: vault_online.VaultOnline,
                           record: Union[vault_record.PasswordRecord, vault_record.TypedRecord],
                           files: List[ParsedFieldValue],
                           stop_on_error: bool) -> None:
        tasks = []
        for file_attachment in files:
            if file_attachment.value.startswith('@'):
                file_name = file_attachment.value[1:]
            else:
                file_name = file_attachment.value
            file_name = os.path.expanduser(file_name)
            if os.path.isfile(file_name):
                task = attachment.FileUploadTask(file_name)
                task.title = file_attachment.label
                tasks.append(task)
            else:
                self.on_warning(f'Upload attachment: file \"{file_name}\" not found')
                if stop_on_error:
                    return

        for task in tasks:
            try:
                self.on_info(f'Uploading {task.name} ...')
                attachment.upload_attachments(vault, record, [task])
            except Exception as e:
                self.on_warning(str(e))
                if stop_on_error:
                    break

    def delete_attachments(self, vault: vault_data.VaultData,
                           record: Union[vault_record.PasswordRecord, vault_record.TypedRecord],
                           file_names: List[str]) -> None:
        if isinstance(record, vault_record.PasswordRecord) and record.attachments:
            for file_name in file_names:
                indexes = [i for i, x in enumerate(record.attachments or [])
                           if x.id == file_name or file_name.lower() in (x.name.lower(), x.title.lower())]
                if len(indexes) > 1:
                    self.on_warning(
                        f'There are multiple file attachments with name \"{file_name}\". Use attachment ID.')
                elif len(indexes) == 1:
                    record.attachments.pop(indexes[0])
        elif isinstance(record, vault_record.TypedRecord):
            facade = record_facades.FileRefRecordFacade()
            facade.record = record
            for file_name in file_names:
                index = next((i for i, x in enumerate(facade.file_ref) if x == file_name), -1)
                if index > 0:
                    facade.file_ref.pop(index)
                else:
                    file_uids = []
                    f_name = file_name.lower()
                    for file_uid in facade.file_ref:
                        file = vault.load_record(file_uid)
                        if isinstance(file, vault_record.FileRecord):
                            if f_name in (file.file_name.lower(), file.title.lower()):
                                file_uids.append(file_uid)
                    if len(file_uids) > 1:
                        self.on_warning(
                            f'There are multiple file attachments with name \"{file_name}\". Use attachment ID.')
                    elif len(file_uids) == 1:
                        facade.file_ref.remove(file_uids[0])


class RecordAddCommand(base.ArgparseCommand, RecordEditMixin):
    parser = argparse.ArgumentParser(prog='record-add', description='Add a record to folder')
    parser.add_argument('--syntax-help', dest='syntax_help', action='store_true',
                        help='Display help on field parameters.')
    parser.add_argument('-f', '--force', dest='force', action='store_true', help='ignore warnings')
    parser.add_argument('-t', '--title', dest='title', action='store', help='record title')
    parser.add_argument('-rt', '--record-type', dest='record_type', action='store', help='record type')
    parser.add_argument('-n', '--notes', dest='notes', action='store', help='record notes')
    parser.add_argument('--folder', dest='folder', action='store',
                        help='folder name or UID to store record')
    parser.add_argument('fields', nargs='*', type=str,
                        help='load record type data from strings with dot notation')
    parser.add_argument('--self-destruct', dest='self_destruct', action='store',
                        metavar='<NUMBER>[(m)inutes|(h)ours|(d)ays]',
                        help='Time period record share URL is valid. The record will be deleted in your vault in 5 minutes since open')


    def __init__(self):
        super().__init__(RecordAddCommand.parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        assert context.vault is not None
        if kwargs.get('syntax_help') is True:
            prompt_utils.output_text(record_fields_description)
            return

        folder_name = kwargs.get('folder') or '.'
        folder, name = folder_utils.try_resolve_path(context, folder_name)
        if name:
            raise base.CommandError(f'\"{folder_name}\" cannot be resolved as a folder')

        self.warnings.clear()
        title = kwargs.get('title')
        if not title:
            raise base.CommandError('Title parameter is required.')
        record_type = kwargs.get('record_type')
        if not record_type:
            raise base.CommandError('Record type parameter is required.')

        fields = kwargs.get('fields', [])
        record_fields: List[ParsedFieldValue] = []
        add_attachments: List[ParsedFieldValue] = []
        rm_attachments: List[ParsedFieldValue] = []
        for field in fields:
            parsed_field = RecordEditMixin.parse_field(field)
            if parsed_field.type == 'file':
                (add_attachments if parsed_field.value else rm_attachments).append(parsed_field)
            else:
                record_fields.append(parsed_field)

        record: Union[vault_record.PasswordRecord, vault_record.TypedRecord]
        if record_type in ('legacy', 'general'):
            record = vault_record.PasswordRecord()
            self.assign_legacy_fields(record, record_fields)
        else:
            rt = context.vault.vault_data.get_record_type_by_name(record_type)
            if not rt:
                raise base.CommandError(f'Record type \"{record_type}\" cannot be found.')

            record = vault_record.TypedRecord()
            record.record_type = record_type
            for rf in rt.fields:
                ref = rf.type
                if not ref:
                    continue
                label = rf.label
                required = rf.required
                field = vault_record.TypedField.create_field(ref, label)
                if required is True:
                    field.required = True
                record.fields.append(field)
            self.assign_typed_fields(record, record_fields)

        record.title = title
        record.notes = self.validate_notes(kwargs.get('notes') or '')

        ignore_warnings = kwargs.get('force') is True
        if len(self.warnings) > 0:
            for warning in self.warnings:
                logger.warning(warning)
            if not ignore_warnings:
                return
        self.warnings.clear()

        if len(add_attachments) > 0:
            self.upload_attachments(context.vault, record, add_attachments, not ignore_warnings)
            if len(self.warnings) > 0:
                for warning in self.warnings:
                    logger.warning(warning)
                if not ignore_warnings:
                    return

        self_destruct = kwargs.get('self_destruct')
        
        record_management.add_record_to_folder(context.vault, record, folder.folder_uid)
        context.environment_variables[constants.LAST_RECORD_UID] = record.record_uid
        if not self_destruct:
            return record.record_uid
        else:
            expiration_period = None
            expiration_period = timeout_utils.parse_timeout(self_destruct)
            SIX_MONTHS_IN_SECONDS = 182 * 24 * 60 * 60
            if expiration_period.total_seconds() > SIX_MONTHS_IN_SECONDS:
                raise base.CommandError('URL expiration period cannot be greater than 6 months.')
            url = record_utils.process_external_share(context=context, expiration_period=expiration_period, record=record)
            expiration_date = datetime.datetime.now() + expiration_period
            formatted_date = expiration_date.strftime('%d/%m/%Y %H:%M:%S')
            message = f'Record self-destructs on {formatted_date} or after being viewed once. Once the link is opened the recipient will have 5 minutes to view the record.\n{url}'
            return message

class RecordUpdateCommand(base.ArgparseCommand, RecordEditMixin):
    parser = argparse.ArgumentParser(prog='record-update', description='Update a record')
    parser.add_argument('--syntax-help', dest='syntax_help', action='store_true',
                                      help='Display help on field parameters.')
    parser.add_argument('-f', '--force', dest='force', action='store_true', help='ignore warnings')
    parser.add_argument('-t', '--title', dest='title', action='store', help='modify record title')
    parser.add_argument('-rt', '--record-type', dest='record_type', action='store', help='record type')
    parser.add_argument('-n', '--notes', dest='notes', action='store', help='append/modify record notes')
    parser.add_argument('-r', '--record', dest='record', action='store',
                                      help='record path or UID')
    parser.add_argument('fields', nargs='*', type=str,
                                      help='load record type data from strings with dot notation')
    def __init__(self):
        super(RecordUpdateCommand, self).__init__(RecordUpdateCommand.parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if kwargs.get('syntax_help') is True:
            prompt_utils.output_text(record_fields_description)
            return

        assert context.vault is not None
        self.warnings.clear()
        record_name = kwargs.get('record')
        if not record_name:
            raise base.CommandError('Record parameter is required.')
        record_info = record_utils.try_resolve_single_record(record_name, context)
        if not record_info:
            raise base.CommandError( f'Record \"{record_name}\" not found.')

        record = context.vault.vault_data.load_record(record_info.record_uid)
        if not isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
            raise base.CommandError(f'Record \"{record_name}\" can not be edited.')

        title = kwargs.get('title')
        if title:
            record.title = title
        notes = kwargs.get('notes')
        if isinstance(notes, str):
            notes = self.validate_notes(notes)
            append_notes = False
            if notes.startswith('+'):
                append_notes = True
                notes = notes[1:].strip()
            if append_notes:
                if record.notes:
                    record.notes += '\n'
                record.notes += notes
            else:
                record.notes = notes

        fields = kwargs.get('fields', [])

        record_fields: List[ParsedFieldValue] = []
        add_attachments: List[ParsedFieldValue] = []
        rm_attachments: List[ParsedFieldValue] = []
        for field in fields:
            parsed_field = RecordEditMixin.parse_field(field)
            if parsed_field.type == 'file':
                (add_attachments if parsed_field.value else rm_attachments).append(parsed_field)
            else:
                record_fields.append(parsed_field)

        if isinstance(record, vault_record.PasswordRecord):
            self.assign_legacy_fields(record, record_fields)
        elif isinstance(record, vault_record.TypedRecord):
            record_type = kwargs.get('record_type')
            if record_type:
                rt = context.vault.vault_data.get_record_type_by_name(record_type)
                if not rt:
                    raise base.CommandError(f'Record type \"{record_type}\" cannot be found.')
                record.record_type = record_type
                self.adjust_typed_record_fields(record, rt.fields)
            self.assign_typed_fields(record, record_fields)
        else:
            raise base.CommandError(f'Record \"{record_name}\" can not be edited.')

        ignore_warnings = kwargs.get('force') is True
        if len(self.warnings) > 0:
            for warning in self.warnings:
                logger.warning(warning)
            if not ignore_warnings:
                return
        self.warnings.clear()

        if len(rm_attachments) > 0:
            names = [x.label for x in rm_attachments if x.label]
            self.delete_attachments(context.vault.vault_data, record, names)
            if len(self.warnings) > 0:
                for warning in self.warnings:
                    logger.warning(warning)
                if not ignore_warnings:
                    return
            self.warnings.clear()

        if len(add_attachments) > 0:
            self.upload_attachments(context.vault, record, add_attachments, not ignore_warnings)
            if len(self.warnings) > 0:
                for warning in self.warnings:
                    logger.warning(warning)
                if not ignore_warnings:
                    return

        record_management.update_record(context.vault, record)


class RecordDeleteAttachmentCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='delete-attachment', description='Delete an attachment from a record',
                                     usage="Example to remove two files for a record: delete-attachment {uid} --name secrets.txt --name photo.jpg")
    parser.add_argument('--name', dest='name', action='append', required=True,
                        help='attachment file name or ID. Can be repeated')
    parser.add_argument('record', action='store', metavar='RECORD', help='record path or UID')

    def __init__(self):
        super(RecordDeleteAttachmentCommand, self).__init__(RecordDeleteAttachmentCommand.parser)

    def execute(self, context, **kwargs):
        record_name = kwargs.get('record')
        if not record_name:
            raise base.CommandError('Record parameter is required.')
        record_info = record_utils.try_resolve_single_record(record_name, context)
        if not record_info:
            raise base.CommandError( f'Record \"{record_name}\" not found.')

        names = kwargs.get('name')
        if names is None:
            raise base.CommandError('File attachment name is required')
        if isinstance(names, str):
            names = [names]

        record = context.vault.vault_data.load_record(record_info.record_uid)
        if not isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
            raise base.CommandError(f'Record \"{record_name}\" can not be edited.')

        deleted_files = set()
        if isinstance(record, vault_record.PasswordRecord):
            if record.attachments:
                for name in names:
                    for atta in record.attachments:
                        if atta.id == name:
                            deleted_files.add(atta.id)
                        elif atta.title and atta.title.lower() == name.lower():
                            deleted_files.add(atta.id)
                        elif atta.name and atta.name.lower() == name.lower():
                            deleted_files.add(atta.id)
                if len(deleted_files) > 0:
                    record.attachments = [x for x in record.attachments if x.id not in deleted_files]
        elif isinstance(record, vault_record.TypedRecord):
            typed_field = record.get_typed_field('fileRef')
            if typed_field and isinstance(typed_field.value, list):
                for name in names:
                    for file_uid in typed_field.value:
                        if file_uid == name:
                            deleted_files.add(file_uid)
                        else:
                            file_record = context.vault.vault_data.load_record(file_uid)
                            if isinstance(file_record, vault_record.FileRecord):
                                if file_record.title.lower() == name.lower():
                                    deleted_files.add(file_uid)
                                elif file_record.file_name.lower() == name.lower():
                                    deleted_files.add(file_uid)
                if len(deleted_files) > 0:
                    typed_field.value = [x for x in typed_field.value if x not in deleted_files]

        if len(deleted_files) == 0:
            logger.info('Attachment(s) not found')
            return

        record_management.update_record(context.vault, record)


class RecordDownloadAttachmentCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='download-attachment', description='Download record attachments')
    parser.add_argument('-r', '--recursive', dest='recursive', action='store_true',
                        help='Download recursively through subfolders')
    parser.add_argument('--out-dir', dest='out_dir', action='store',
                        help='Local folder for downloaded files')
    parser.add_argument('--preserve-dir', dest='preserve_dir', action='store_true',
                        help='Preserve vault folder structure')
    parser.add_argument('--record-title', dest='record_title', action='store_true',
                        help='Add record title to attachment file.')
    parser.add_argument('records', nargs='*', metavar='PATH', help='Record or folder path or UID')

    def __init__(self):
        super(RecordDownloadAttachmentCommand, self).__init__(RecordDownloadAttachmentCommand.parser)

    def execute(self, context, **kwargs):
        records = kwargs.get('records')
        if not records:
            raise base.CommandError('Records parameter is required.')
        if isinstance(records, str):
            records = [records]

        record_uids = set()
        for record in records:
            record_uids.update(record_utils.resolve_records(record, context, recursive=kwargs.get('recursive') is True))

        if len(record_uids) == 0:
            all_names = ', '.join(records)
            raise base.CommandError(f'Record(s) "{all_names}" not found')

        output_dir = kwargs.get('out_dir')
        if output_dir:
            output_dir = os.path.expanduser(output_dir)
        else:
            output_dir = os.getcwd()
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)

        preserve_dir = kwargs.get('preserve_dir') is True
        record_title = kwargs.get('record_title') is True
        for record_uid in record_uids:
            attachments = list(attachment.prepare_attachment_download(context.vault, record_uid))
            if len(attachments) == 0:
                continue

            subfolder_path = ''
            if preserve_dir:
                folder = next((x for x in vault_utils.get_folders_for_record(context.vault.vault_data, record_uid)), None)
                if folder:
                    subfolder_path = vault_utils.get_folder_path(context.vault.vault_data, folder.folder_uid, os.sep)
                    subfolder_path = ''.join(x for x in subfolder_path if x.isalnum() or x == os.sep)
                    subfolder_path = subfolder_path.replace(2*os.sep, os.sep)
            if subfolder_path:
                subfolder_path = os.path.join(output_dir, subfolder_path)
                if not os.path.isdir(subfolder_path):
                    os.makedirs(subfolder_path)
            else:
                subfolder_path = output_dir

            title = ''
            if record_title:
                record = context.vault.vault_data.load_record(record_uid)
                title = record.title
                title = ''.join(x for x in title if x.isalnum() or x.isspace())

            for atta in attachments:
                file_name = atta.title
                if title:
                    file_name = f'{title}-{atta.title}'
                file_name = os.path.basename(file_name)
                name = os.path.join(subfolder_path, file_name)
                if os.path.isfile(name):
                    base_name, ext = os.path.splitext(file_name)
                    name = os.path.join(subfolder_path, f'{base_name}({record_uid}){ext}')
                if os.path.isfile(name):
                    base_name, ext = os.path.splitext(file_name)
                    name = os.path.join(subfolder_path, f'{base_name}({atta.file_id}){ext}')
                atta.download_to_file(str(name))


class RecordUploadAttachmentCommand(base.ArgparseCommand):
    parser = argparse.ArgumentParser(prog='upload-attachment', description='Upload record attachments')
    parser.add_argument('--file', dest='file', action='append', required=True, help='file name to upload')
    parser.add_argument('record', action='store', metavar='PATH', help='record path or UID')

    def __init__(self):
        super(RecordUploadAttachmentCommand, self).__init__(RecordUploadAttachmentCommand.parser)

    def execute(self, context, **kwargs):
        record_name = kwargs.get('record')
        if not record_name:
            raise base.CommandError('Record parameter is required.')

        record_info = record_utils.try_resolve_single_record(record_name, context)
        if not record_info:
            raise base.CommandError( f'Record \"{record_name}\" not found.')

        upload_tasks = []
        files = kwargs.get('file')
        if isinstance(files, list):
            for name in files:
                file_name = os.path.abspath(os.path.expanduser(name))
                if os.path.isfile(file_name):
                    upload_tasks.append(attachment.FileUploadTask(file_name))
                else:
                    raise base.CommandError(f'File "{name}" does not exists')

        if len(upload_tasks) == 0:
            raise base.CommandError('No files to upload')

        record = context.vault.vault_data.load_record(record_info.record_uid)
        if not isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
            raise base.CommandError(f'Record \"{record_name}\" can not be edited.')

        attachment.upload_attachments(context.vault, record, upload_tasks)
        record_management.update_record(context.vault, record)


class RecordDeleteCommand(base.ArgparseCommand):

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='rm',
            description='Remove a record'
        )
        RecordDeleteCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)

    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '-f', '--force', dest='force', action='store_true', help='do not prompt'
        )
        parser.add_argument(
            'records', nargs='*', type=str, help='record path or UID. Can be multiple.'
        )

    def execute(self, context: KeeperParams, **kwargs) -> None:
        if not context.vault:
            raise ValueError("Vault is not initialized.")

        record_uids = kwargs.get('records')
        force = kwargs.get('force') or False

        if not isinstance(record_uids, list):
            if isinstance(record_uids, str):
                record_uids = [record_uids]
            else:
                record_uids = []

        confirm_fn = None if force else record_utils.default_confirm

        record_management.delete_vault_objects(
            vault=context.vault,
            vault_objects=record_uids,
            confirm=confirm_fn
        )


class RecordGetCommand(base.ArgparseCommand):
    """Command to get details of Records, Folders, Teams by UID or title."""

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='get',
            description='Get the details of a Record/Folder/Team by UID or title'
        )
        RecordGetCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)

    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            '--unmask', dest='unmask', action='store_true', 
            help='display hidden field content'
        )
        parser.add_argument(
            '--legacy', dest='legacy', action='store_true', 
            help='json output: display typed records as legacy'
        )
        parser.add_argument(
            '--format', dest='format', action='store', 
            choices=['detail', 'json', 'password', 'fields'],
            default='detail', 
            help='output format as detail, json, password, fields'
        )
        parser.add_argument(
            '-f', '--folder', dest='folder', action='store',
            help='folder UID or title to search for'
        )
        parser.add_argument(
            '-t', '--team', dest='team', action='store',
            help='team UID or title to search for'
        )
        parser.add_argument(
            '-r', '--record', dest='record', action='store',
            help='record UID or title to search for'
        )
        parser.add_argument(
            'uid', type=str, action='store', nargs='?', default=None,
            help='UID or title to search for (optional when using -f, -t, or -r flags)'
        )

    def execute(self, context: KeeperParams, **kwargs):
        """Execute the get command based on the provided parameters."""
        self._validate_context(context)
        
        uid = kwargs.get('uid')
        output_format = kwargs.get('format', 'detail')
        unmask = kwargs.get('unmask', False)
        folder = kwargs.get('folder')
        team = kwargs.get('team')
        record = kwargs.get('record')
        
        if folder:
            shared_folder = self._find_shared_folder(context.vault, folder)
            if shared_folder:
                target_object = ('shared_folder', shared_folder)
            else:
                folder = self._find_folder(context.vault, folder)
                if folder:
                    target_object = ('folder', folder)
                else:
                    raise base.CommandError('The given UID or title is not a valid folder')
        elif team:
            team = self._find_team(context, team)
            if team:
                target_object = ('team', team)
            else:
                raise base.CommandError('The given UID or title is not a valid team')
        elif record:
            record = self._find_record(context.vault, record)
            if record:
                target_object = ('record', record)
            else:
                raise base.CommandError('The given UID or title is not a valid record')
        elif uid:
            target_object = self._find_target_object(context, uid)
        else:
            raise base.CommandError('Either UID parameter or one of -f, -t, -r flags is required')

        if not target_object:
            raise base.CommandError('The given UID is not a valid Keeper Object')
        
        self._display_object(context, target_object, output_format, unmask)

    def _validate_context(self, context: KeeperParams):
        """Validate that the vault is properly initialized."""
        if not context.vault:
            raise ValueError("Vault is not initialized.")

    def _find_target_object(self, context: KeeperParams, uid_or_title: str):
        """Find a Keeper object (record, folder, shared folder, or team) by UID or title."""
        
        vault = context.vault
        shared_folder = self._find_shared_folder(vault, uid_or_title)
        if shared_folder:
            return ('shared_folder', shared_folder)
        
        folder = self._find_folder(vault, uid_or_title)
        if folder:
            return ('folder', folder)
        
        team = self._find_team(context, uid_or_title)
        if team:
            return ('team', team)
        
        record = self._find_record(vault, uid_or_title)
        if record:
            return ('record', record)
        
        return None

    def _find_record(self, vault: vault_data.VaultData, uid_or_title: str):
        """Find a record by UID or title."""
        return next(
            (r for r in vault.vault_data.records() 
             if r.record_uid == uid_or_title or r.title == uid_or_title), 
            None
        )

    def _find_shared_folder(self, vault: vault_data.VaultData, uid_or_title: str):
        """Find a shared folder by UID or name."""
        return next(
            (f for f in vault.vault_data.shared_folders() 
             if f.shared_folder_uid == uid_or_title or f.name == uid_or_title), 
            None
        )
    
    def _find_folder(self, vault: vault_data.VaultData, uid_or_title: str):
        """Find a folder by UID or name."""
        return next(
            (f for f in vault.vault_data.folders() 
             if f.folder_uid == uid_or_title or f.name == uid_or_title), 
            None
        )
    
    def _find_team(self, context: KeeperParams, uid_or_title: str):
        """Find a team by UID or name."""
        if not context.enterprise_data:
            raise base.CommandError('You must be an enterprise admin to use this command')

        team = enterprise_utils.TeamUtils.resolve_single_team(context.enterprise_data, uid_or_title)
        return team

    def _display_object(self, context: KeeperParams, target_object, output_format: str, unmask: bool):
        """Display the target object in the specified format."""
        object_type, object_data = target_object
        vault = context.vault
        if object_type == 'record':
            self._display_record(vault, object_data, output_format, unmask)
        elif object_type == 'shared_folder':
            self._display_shared_folder(vault, object_data, output_format)
        elif object_type == 'folder':
            self._display_folder(vault, object_data, output_format)
        elif object_type == 'team':
            self._display_team(context, object_data, output_format)

    def _display_record(self, vault: vault_data.VaultData, record, output_format: str, unmask: bool):
        """Display a record in the specified format."""
        record_uid = record.record_uid
        dispatch = {
            'json': lambda: self._display_record_json(vault, record_uid, unmask),
            'password': lambda: self._display_record_password(vault, record_uid),
            'fields': lambda: self._display_record_fields(vault, record_uid, unmask)
        }

        display_func = dispatch.get(output_format, lambda: self._display_record_detail(vault, record_uid, unmask))
        display_func()

    def _display_shared_folder(self, vault: vault_data.VaultData, shared_folder, output_format: str):
        """Display a shared folder in the specified format."""
        if output_format == 'json':
            self._display_shared_folder_json(vault, shared_folder.shared_folder_uid)
        else:  # detail format
            self._display_shared_folder_detail(vault, shared_folder.shared_folder_uid)

    def _display_folder(self, vault: vault_data.VaultData, folder, output_format: str):
        """Display a folder in the specified format."""
        if output_format == 'json':
            self._display_folder_json(vault, folder.folder_uid)
        else:  # detail format
            self._display_folder_detail(vault, folder.folder_uid)

    def _display_team(self, context: KeeperParams, team, output_format: str):
        """Display a team in the specified format."""
        if output_format == 'json':
            self._display_team_json(context, team.team_uid)
        else:  # detail format
            self._display_team_detail(context, team.team_uid)
    
    def _display_record_json(self, vault: vault_data.VaultData, uid: str, unmask: bool = False):
        """Display record information in JSON format."""
        record = vault.vault_data.get_record(record_uid=uid)
        record_data = vault.vault_data.load_record(record_uid=uid)
        
        output = self._build_record_json_output(record, record_data, uid, unmask)
        
        self._add_share_info_to_json(vault, uid, output)
        
        logger.info(json.dumps(output, indent=2))

    def _build_record_json_output(self, record, record_data, uid: str, unmask: bool = False):
        """Build the JSON output structure for a record."""
        output = {
            'Record UID:': uid,
            'Type': record.record_type,
            'Title:': record.title,
        }
        
        if isinstance(record_data, vault_record.PasswordRecord):
            self._add_password_record_json_fields(record_data, output, unmask)
        elif isinstance(record_data, vault_record.TypedRecord):
            self._add_typed_record_json_fields(record_data, output, unmask)
        elif isinstance(record_data, vault_record.FileRecord):
            self._add_file_record_json_fields(record_data, output)
        else:
            raise ValueError('Record data could not be displayed. Record is of unsupported type for this command(eg Application record)')

        output['Last Modified:'] = datetime.datetime.fromtimestamp(record_data.client_time_modified / 1000).strftime('%Y-%m-%d %H:%M:%S') if record_data.client_time_modified else None
        output['Version:'] = record.version
        output['Revision'] = record.revision
        
        return output

    def _add_password_record_json_fields(self, record_data: vault_record.PasswordRecord, output: dict, unmask: bool = False):
        """Add password record specific fields to JSON output."""
        output['Notes:'] = record_data.notes
        output['$login:'] = record_data.login
        output['$password:'] = '********' if not unmask else record_data.password
        output['$link:'] = record_data.link

        if record_data.totp:
            output['Totp:'] = '********' if not unmask else record_data.totp
        
        if record_data.attachments:
            output['Attachments:'] = [{
                'Id': a.get('id'),
                'Name': a.get('name'),
                'Size': a.get('size')
            } for a in record_data.attachments]
        
        if record_data.custom:
            custom_output = []
            for field in record_data.custom:
                field_data = vault_extensions.extract_typed_field(field)
                if not unmask and self._is_sensitive_field_type(field.type):
                    if isinstance(field_data, dict) and 'value' in field_data:
                        field_data['value'] = '********'
                    elif isinstance(field_data, str):
                        field_data = '********'
                custom_output.append(field_data)
            output['Custom fields:'] = custom_output

    def _add_typed_record_json_fields(self, record_data: vault_record.TypedRecord, output: dict, unmask: bool = False):
        """Add typed record specific fields to JSON output."""
        output['Notes:'] = record_data.notes
        
        fields_output = []
        for field in record_data.fields:
            field_data = vault_extensions.extract_typed_field(field)
            if not unmask and self._is_sensitive_field_type(field.type):
                if isinstance(field_data, dict) and 'value' in field_data:
                    field_data['value'] = '********'
                elif isinstance(field_data, str):
                    field_data = '********'
            fields_output.append(field_data)
        output['Fields:'] = fields_output
        
        custom_output = []
        for field in record_data.custom:
            field_data = vault_extensions.extract_typed_field(field)
            if not unmask and self._is_sensitive_field_type(field.type):
                if isinstance(field_data, dict) and 'value' in field_data:
                    field_data['value'] = '********'
                elif isinstance(field_data, str):
                    field_data = '********'
            custom_output.append(field_data)
        output['Custom:'] = custom_output

    def _add_file_record_json_fields(self, record_data: vault_record.FileRecord, output: dict):
        """Add file record specific fields to JSON output."""
        output['Name:'] = record_data.file_name
        output['MIME Type:'] = record_data.mime_type
        output['Size:'] = record_data.size

    def _add_share_info_to_json(self, vault: vault_data.VaultData, uid: str, output: dict):
        """Add share information to JSON output."""
        share_infos = share_utils.get_record_shares(vault=vault, record_uids=[uid])
        if share_infos and len(share_infos) > 0:
            share_info = share_infos[0]
            shares = share_info.get('shares', {})
            record_shares = shares.get('user_permissions')
            folder_shares = shares.get('shared_folder_permissions')

            if record_shares:
                output['User Shares:'] = record_shares
            if folder_shares:
                output['Shared Folders:'] = folder_shares
    
    def _display_shared_folder_json(self, vault: vault_data.VaultData, uid: str):
        """Display shared folder information in JSON format."""
        shared_folder = vault.vault_data.load_shared_folder(shared_folder_uid=uid)
        output = {
            'Shared Folder UID:': uid,
            'Name:': shared_folder.name,
            'Default Manage Records:': shared_folder.default_manage_records,
            'Default Manage Users:': shared_folder.default_manage_users,
            'Default Can Edit:': shared_folder.default_can_edit,
            'Default Can Share:': shared_folder.default_can_share
        }
        
        if len(shared_folder.record_permissions) > 0:
            output['Record Permissions:'] = [{
                'record_uid': r.record_uid,
                'can_edit': r.can_edit,
                'can_share': r.can_share
            } for r in shared_folder.record_permissions]
            
        if len(shared_folder.user_permissions) > 0:
            output['User Permissions:'] = [{
                'user_uid': u.user_uid,
                'name': u.name,
                'user_type': u.user_type,
                'manage_records': u.manage_records,
                'manage_users': u.manage_users
            } for u in shared_folder.user_permissions]
        
        logger.info(json.dumps(output, indent=2))
    
    def _display_folder_json(self, vault: vault_data.VaultData, uid: str):
        """Display folder information in JSON format."""
        folder = vault.vault_data.get_folder(folder_uid=uid)
        output = {
            'Folder UID:': uid,
            'Parent Folder UID:': folder.parent_uid,
            'Folder Type:': folder.folder_type,
            'Name:': folder.name
        }
        logger.info(json.dumps(output, indent=2))
    
    def _display_team_json(self, context: KeeperParams, uid: str):
        """Display team information in JSON format."""
        team = context.enterprise_data.teams.get_entity(uid)
        user = enterprise_utils.UserUtils.resolve_single_user(context.enterprise_data, context.username)
        team_users = {x.team_uid for x in context.enterprise_data.team_users.get_links_by_object(user.enterprise_user_id)}
        if team.team_uid not in team_users:
            logger.info(f'User {context.username} does not belong to team {team.name}')
        output = {
            'Team UID:': uid,
            'Name:': team.name
        }
        logger.info(json.dumps(output, indent=2))
    
    def _display_record_detail(self, vault: vault_data.VaultData, uid: str, unmask: bool):
        """Display record information in detailed format."""
        record = vault.vault_data.get_record(record_uid=uid)
        record_data = vault.vault_data.load_record(record_uid=uid)
        
        self._display_record_header(record, uid)
        
        if isinstance(record_data, vault_record.PasswordRecord):
            self._display_password_record_detail(record_data, unmask)
        elif isinstance(record_data, vault_record.TypedRecord):
            self._display_typed_record_detail(record_data, unmask)
        elif isinstance(record_data, vault_record.FileRecord):
            self._display_file_record_detail(record_data)
        
        self._display_share_information(vault, uid)
        self._display_share_admins(vault, uid)

    def _display_record_header(self, record, uid: str):
        """Display the header information for a record."""
        logger.info('')
        logger.info('{0:>20s}: {1:<20s}'.format('UID', uid))
        logger.info('{0:>20s}: {1:<20s}'.format('Type', record.record_type or ''))
        if record.title:
            logger.info('{0:>20s}: {1:<20s}'.format('Title', record.title))

    def _display_password_record_detail(self, record_data: vault_record.PasswordRecord, unmask: bool):
        """Display password record details."""
        if record_data.login:
            logger.info('{0:>20s}: {1:<20s}'.format('Login', record_data.login))
        if record_data.password:
            password_display = record_data.password if unmask else '********'
            logger.info('{0:>20s}: {1:<20s}'.format('Password', password_display))
        if record_data.link:
            logger.info('{0:>20s}: {1:<20s}'.format('URL', record_data.link))

        self._display_custom_fields(record_data.custom)
        self._display_notes(record_data.notes)
        self._display_attachments(record_data.attachments)
        self._display_totp(record_data.totp, unmask)

    def _display_typed_record_detail(self, record_data: vault_record.TypedRecord, unmask: bool):
        """Display typed record details."""
        # Display typed record fields
        for field in record_data.fields:
            if field.value:
                field_value = field.get_default_value()
                if self._is_sensitive_field_type(field.type) and not unmask:
                    field_value = '********'
                logger.info('{0:>20s}: {1:<20s}'.format(field.type, str(field_value)))
        
        # Display custom fields
        for field in record_data.custom:
            if field.value:
                field_value = field.get_default_value()
                if self._is_sensitive_field_type(field.type) and not unmask:
                    field_value = '********'
                logger.info('{0:>20s}: {1:<20s}'.format(field.type, str(field_value)))
        
        self._display_notes(record_data.notes)

    def _display_file_record_detail(self, record_data: vault_record.FileRecord):
        """Display file record details."""
        logger.info('{0:>20s}: {1:<20s}'.format('File Name', record_data.file_name))
        logger.info('{0:>20s}: {1:<20s}'.format('MIME Type', record_data.mime_type))
        logger.info('{0:>20s}: {1:<20s}'.format('Size', str(record_data.size)))

    def _display_custom_fields(self, custom_fields):
        """Display custom fields."""
        if custom_fields:
            for c in custom_fields:
                logger.info('{0:>20s}: {1:<s}'.format(str(c.name), str(c.value)))

    def _display_notes(self, notes: str):
        """Display notes with proper formatting."""
        if notes:
            lines = notes.split('\n')
            for i in range(len(lines)):
                logger.info('{0:>21s} {1}'.format('Notes:' if i == 0 else '', lines[i].strip()))

    def _display_attachments(self, attachments):
        """Display attachment information."""
        if attachments:
            for i in range(len(attachments)):
                atta = attachments[i]
                size = atta.size or 0
                scale = 'b'
                if size > 0:
                    if size > 1000:
                        size = size / 1024
                        scale = 'Kb'
                    if size > 1000:
                        size = size / 1024
                        scale = 'Mb'
                    if size > 1000:
                        size = size / 1024
                        scale = 'Gb'
                sz = '{0:.2f}'.format(size).rstrip('0').rstrip('.')
                logger.info('{0:>21s} {1:<20s} {2:>6s}{3:<2s} {4:>6s}: {5}'.format(
                    'Attachments:' if i == 0 else '', atta.title or atta.name, sz, scale, 'ID', atta.id))

    def _display_totp(self, totp: str, unmask: bool):
        """Display TOTP information."""
        if totp:
            totp_display = totp if unmask else '********'
            logger.info('{0:>20s}: {1}'.format('TOTP URL', totp_display))
            code, remain, _ = record_utils.get_totp_code(totp)
            if code:
                logger.info('{0:>20s}: {1:<20s} valid for {2} sec'.format('Two Factor Code', code, remain))

    def _display_share_information(self, vault: vault_data.VaultData, uid: str):
        """Display share information for a record."""
        share_infos = share_utils.get_record_shares(vault=vault, record_uids=[uid])
        if not share_infos or len(share_infos) == 0:
            return
            
        share_info = share_infos[0]
        shares = share_info.get('shares', {})
        record_shares = shares.get('user_permissions')
        folder_shares = shares.get('shared_folder_permissions')

        if record_shares:
            self._display_user_permissions(record_shares)
        if folder_shares:
            self._display_folder_permissions(folder_shares)

    def _display_user_permissions(self, record_shares):
        """Display user permissions."""
        logger.info('')
        logger.info('User Permissions:')
        for user in record_shares:
            logger.info('')
            if 'username' in user:
                logger.info('User: ' + user['username'])
            if 'user_uid' in user:
                logger.info('User UID: ' + user['user_uid'])
            elif 'accountUid' in user:
                logger.info('User UID: ' + user['accountUid'])
            
            # Handle both possible spellings of sharable/shareable
            shareable = user.get('sharable') or user.get('shareable', False)
            
            logger.info('Shareable: ' + ('Yes' if shareable else 'No'))
            logger.info('Read-Only: ' + ('Yes' if not shareable else 'No'))
        logger.info('')

    def _display_folder_permissions(self, folder_shares):
        """Display folder permissions."""
        logger.info('')
        logger.info('Shared Folder Permissions:')
        for sf in folder_shares:
            logger.info('')
            if 'shared_folder_uid' in sf:
                logger.info('Shared Folder UID: ' + sf['shared_folder_uid'])
            if 'user_uid' in sf:
                logger.info('User UID: ' + sf['user_uid'])
            elif 'accountUid' in sf:
                logger.info('User UID: ' + sf['accountUid'])
            
            if sf.get('manage_users', False) is True:
                logger.info('Manage Users: True')
            if sf.get('manage_records', False) is True:
                logger.info('Manage Records: True')
            if sf.get('can_edit', False) is True:
                logger.info('Can Edit: True')
            if sf.get('can_share', False) is True:
                logger.info('Can Share: True')
        logger.info('')

    def _display_share_admins(self, vault: vault_data.VaultData, uid: str):
        """Display share admins for a record."""
        admins = record_utils.get_share_admins_for_record(vault=vault, record_uid=uid)
        if admins:
            logger.info('')
            logger.info('Share Admins:')
            for admin in admins:
                logger.info(admin)
        
    def _display_shared_folder_detail(self, vault: vault_data.VaultData, uid: str):
        """Display shared folder information in detailed format."""
        shared_folder = vault.vault_data.load_shared_folder(shared_folder_uid=uid)
        logger.info('') 
        logger.info('{0:>25s}: {1:<20s}'.format('Shared Folder UID', shared_folder.shared_folder_uid))
        logger.info('{0:>25s}: {1}'.format('Name', shared_folder.name))
        logger.info('{0:>25s}: {1}'.format('Default Manage Records', shared_folder.default_manage_records))
        logger.info('{0:>25s}: {1}'.format('Default Manage Users', shared_folder.default_manage_users))
        logger.info('{0:>25s}: {1}'.format('Default Can Edit', shared_folder.default_can_edit))
        logger.info('{0:>25s}: {1}'.format('Default Can Share', shared_folder.default_can_share))

        if len(shared_folder.record_permissions) > 0:
            logger.info('')
            logger.info('{0:>25s}:'.format('Record Permissions'))
            for r in shared_folder.record_permissions:
                logger.info('{0:>25s}: {1}'.format(r.record_uid, folder_utils.record_permission_to_string({
                    'can_edit': r.can_edit,
                    'can_share': r.can_share
                })))

        if len(shared_folder.user_permissions) > 0:
            logger.info('')
            logger.info('{0:>25s}:'.format('User Permissions'))
            for u in shared_folder.user_permissions:
                logger.info('{0:>25s}: {1}'.format(u.name or u.user_uid, folder_utils.user_permission_to_string({
                    'manage_users': u.manage_users,
                    'manage_records': u.manage_records
                })))

        logger.info('')
    
    def _display_folder_detail(self, vault: vault_data.VaultData, uid: str):
        """Display folder information in detailed format."""
        folder = vault.vault_data.get_folder(folder_uid=uid)
        logger.info('')
        logger.info('{0:>20s}: {1:<20s}'.format('Folder UID', folder.folder_uid))
        logger.info('{0:>20s}: {1:<20s}'.format('Folder Type', folder.folder_type))
        logger.info('{0:>20s}: {1}'.format('Name', folder.name))
        if folder.parent_uid:
            logger.info('{0:>20s}: {1:<20s}'.format('Parent Folder UID', folder.parent_uid))
        if folder.folder_type == 'shared_folder_folder':
            logger.info('{0:>20s}: {1:<20s}'.format('Shared Folder UID', folder.folder_scope_uid))
    
    def _display_team_detail(self, context: KeeperParams, uid: str):
        """Display team information in detailed format."""
        team = context.enterprise_data.teams.get_entity(uid)

        user = enterprise_utils.UserUtils.resolve_single_user(context.enterprise_data, context.username)
        team_users = {x.team_uid for x in context.enterprise_data.team_users.get_links_by_object(user.enterprise_user_id)}
        team_user = True
        if team.team_uid not in team_users:
            logger.info(f'User {context.username} does not belong to team {team.name}')
            team_user = False

        logger.info('')
        logger.info('{0:>20s}: {1:<20s}'.format('Team UID', team.team_uid))
        logger.info('{0:>20s}: {1}'.format('Name', team.name))
        if team_user:
            logger.info('{0:>20s}: {1}'.format('Restrict Edit', team.restrict_edit))
            logger.info('{0:>20s}: {1}'.format('Restrict View', team.restrict_view))
            logger.info('{0:>20s}: {1}'.format('Restrict Share', team.restrict_share))
        logger.info('')
    
    def _display_record_password(self, vault: vault_data.VaultData, uid: str):
        """Display only the password field of a record."""
        record_data = vault.vault_data.load_record(record_uid=uid)
        if isinstance(record_data, vault_record.PasswordRecord):
            logger.info(record_data.password)
        elif isinstance(record_data, vault_record.TypedRecord):
            password_field = record_data.get_typed_field('password')
            if password_field and password_field.value:
                logger.info(password_field.get_default_value(str))
        else:
            logger.info('No password field found in this record type')
    
    def _display_record_fields(self, vault: vault_data.VaultData, uid: str, unmask: bool):
        """Display record fields in JSON format."""
        record = vault.vault_data.get_record(record_uid=uid)
        record_data = vault.vault_data.load_record(record_uid=uid)

        fields = []
        normalize_titles = {}

        # Get share information
        share_infos = share_utils.get_record_shares(vault=vault, record_uids=[uid])
        record_shares = []
        folder_shares = []
        if share_infos and len(share_infos) > 0:
            share_info = share_infos[0]
            shares = share_info.get('shares', {})
            record_shares = shares.get('user_permissions', [])
            folder_shares = shares.get('shared_folder_permissions', [])

        self._add_record_properties_to_fields(record, record_shares, folder_shares, fields, normalize_titles)
        
        self._add_typed_fields_to_output(record_data, unmask, fields, normalize_titles)
        
        if record_data.notes:
            field = {
                'name': 'Notes',
                'value': record_data.notes,
            }
            fields.append(field)

        logger.info(json.dumps(fields, indent=2))

    def _add_record_properties_to_fields(self, record, record_shares, folder_shares, fields, normalize_titles):
        """Add record properties to the fields list."""
        record_props = {
            'title': record.title,
            'record_uid': record.record_uid,
            'revision': record.revision,
            'version': record.version,
            'shared': True if record_shares or folder_shares else False,
        }
        for prop_name, prop_value in record_props.items():
            normalize_titles[prop_name.lower()] = prop_name
            key = prop_name
            field = {
                'name': key,
                'value': prop_value,
            }
            fields.append(field)

    def _add_typed_fields_to_output(self, record_data, unmask: bool, fields, normalize_titles):
        """Add typed fields to the output."""
        for field_type, field_label, field_value in record_data.enumerate_fields():
            key = field_label or field_type
            if key in normalize_titles:
                key = normalize_titles[key.lower()]
            normalize_titles[key.lower()] = key
            
            if unmask or not self._is_sensitive_field_type(field_type):
                var_value = field_value
            else:
                var_value = '********'

            field_obj = {
                'name': key,
                'value': var_value,
            }
            fields.append(field_obj)
    
    def _is_sensitive_field_type(self, field_type: str) -> bool:
        """Check if a field type is considered sensitive and should be masked."""
        sensitive_types = {
            'password', 'secret', 'otp', 'privateKey', 'pinCode', 
            'oneTimeCode', 'keyPair', 'licenseNumber'
        }
        return field_type in sensitive_types


class RecordSearchCommand(base.ArgparseCommand):
    """Command for searching vault records, shared folders, and teams."""
    
    DEFAULT_CATEGORIES = 'rst'
    MAX_DETAILS_THRESHOLD = 5
    DEFAULT_COLUMN_WIDTH = 40

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='search', description='Search the vault for records. Can use a regular expression.'
        )
        RecordSearchCommand.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            'pattern', nargs='?', type=str, action='store', help='search pattern'
        )
        parser.add_argument(
            '-v', '--verbose', dest='verbose', action='store_true', help='verbose output'
        )
        parser.add_argument(
            '-c', '--categories', dest='categories', action='store',
            help='One or more of these letters for categories to search: "r" = records, '
                    '"s" = shared folders, "t" = teams'
        )
    
    def execute(self, context: KeeperParams, **kwargs):
        """Main execution method for the search command."""
        if not context.vault:
            raise ValueError('Vault is not initialized. Login to initialize the vault.')

        search_config = self._prepare_search_config(kwargs)
        self._perform_search(context.vault, search_config, context)

    def _prepare_search_config(self, kwargs: dict) -> dict:
        """Prepare search configuration from command line arguments."""
        pattern = kwargs.get('pattern') or ''
        
        if pattern == '*':
            pattern = '.*'

        verbose = kwargs.get('verbose') is True
        
        return {
            'pattern': pattern,
            'categories': (kwargs.get('categories') or self.DEFAULT_CATEGORIES).lower(),
            'verbose': verbose,
            'skip_details': not verbose
        }

    def _perform_search(self, vault: vault_online.VaultOnline, config: dict, context: KeeperParams):
        """Perform the search across all specified categories."""
        # Validate categories
        valid_categories = set('rst')
        requested_categories = set(config['categories'])
        if not requested_categories.issubset(valid_categories):
            logger.warning(f"Invalid categories specified: {requested_categories - valid_categories}. "
                          f"Using valid categories: {requested_categories & valid_categories}")
            config['categories'] = ''.join(requested_categories & valid_categories)
        
        # Store search results for each category
        search_results = {}
        total_found = 0
        max_results_per_category = 1000

        # Search in each requested category
        if 'r' in config['categories']:
            try:
                records = context.vault.vault_data.find_records(criteria=config['pattern'], record_type=None, record_version=None)
                search_results['records'] = list(itertools.islice(records, max_results_per_category))
                total_found += len(search_results['records'])
            except Exception as e:
                logger.error(f"Error searching records: {e}")
                search_results['records'] = []
        
        if 's' in config['categories']:
            try:
                shared_folders = vault.vault_data.find_shared_folders(criteria=config['pattern'])
                search_results['shared_folders'] = list(itertools.islice(shared_folders, max_results_per_category))
                total_found += len(search_results['shared_folders'])
            except Exception as e:
                logger.error(f"Error searching shared folders: {e}")
                search_results['shared_folders'] = []
        
        if 't' in config['categories']:
            try:
                teams = vault.vault_data.find_teams(criteria=config['pattern'])
                search_results['teams'] = list(itertools.islice(teams, max_results_per_category))
                total_found += len(search_results['teams'])
            except Exception as e:
                logger.error(f"Error searching teams: {e}")
                search_results['teams'] = []
        
        # Check if any objects were found in any of the requested categories
        if total_found == 0:
            categories_str = ', '.join(requested_categories)
            raise base.CommandError(f"No objects found in any of the requested categories: {categories_str}")
        
        # Display results after all searches are completed
        self._display_all_search_results(search_results, config, context, vault)

    def _display_all_search_results(self, search_results: dict, config: dict, context: KeeperParams, vault: vault_online.VaultOnline):
        """Display all search results after all searches are completed."""
        if 'records' in search_results and search_results['records']:
            logger.info('')
            self._display_records_table(search_results['records'], config['verbose'])
            
            if config['verbose'] and len(search_results['records']) < self.MAX_DETAILS_THRESHOLD:
                self._display_record_details(search_results['records'], context)
        
        if 'shared_folders' in search_results and search_results['shared_folders']:
            logger.info('')
            self._display_shared_folders(search_results['shared_folders'], config['skip_details'], vault)
        
        if 'teams' in search_results and search_results['teams']:
            logger.info('')
            self._display_teams(search_results['teams'], config['skip_details'], vault)

    def _search_records(self, config: dict, context: KeeperParams):
        """Search and display records matching the pattern."""
        try:
            records = context.vault.vault_data.find_records(criteria=config['pattern'], record_type=None, record_version=None)

            logger.info('')
            self._display_records_table(records, config['verbose'])
            
            if config['verbose'] and len(records) < self.MAX_DETAILS_THRESHOLD:
                self._display_record_details(records, context)
        except Exception as e:
            logger.error(f"Error searching records: {e}")

    def _search_shared_folders(self, vault: vault_online.VaultOnline, config: dict):
        """Search and display shared folders matching the pattern."""
        try:
            shared_folders = vault.vault_data.find_shared_folders(criteria=config['pattern'])
            if shared_folders:
                logger.info('')
                self._display_shared_folders(shared_folders, config['skip_details'], vault)
        except Exception as e:
            logger.error(f"Error searching shared folders: {e}")

    def _search_teams(self, vault: vault_online.VaultOnline, config: dict):
        """Search and display teams matching the pattern."""
        try:
            teams = vault.vault_data.find_teams(criteria=config['pattern'])
            if teams:
                logger.info('')
                self._display_teams(teams, config['skip_details'], vault)
        except Exception as e:
            logger.error(f"Error searching teams: {e}")

    def _display_records_table(self, records: Iterable[vault_record.KeeperRecordInfo], verbose: bool):
        """Display records in a formatted table."""
        table = []
        headers = ['Record UID', 'Type', 'Title', 'Description']
        
        for record in records:
            row = [
                record.record_uid, 
                record.record_type, 
                record.title,
                record.description
            ]
            table.append(row)
        
        table.sort(key=lambda x: (x[2] or '').lower())
        
        column_width = None if verbose else self.DEFAULT_COLUMN_WIDTH
        report_utils.dump_report_data(
            table, headers, row_number=True, column_width=column_width
        )

    def _display_record_details(self, records: Iterable[vault_record.KeeperRecordInfo], context: KeeperParams):
        """Display detailed information for records when verbose mode is enabled."""
        get_command = RecordGetCommand()
        for record in records:
            kwargs = {'uid': record.record_uid, 'record': True}
            get_command.execute(context, **kwargs)

    def _display_shared_folders(self, shared_folders: Iterable[vault_types.SharedFolder], 
                               skip_details: bool, vault: vault_online.VaultOnline):
        """Display shared folders in a formatted table with optional details."""
        shared_folders_list = list(shared_folders)
        
        shared_folders_list.sort(key=lambda x: (x.name or ' ').lower())

        if shared_folders_list:
            self._display_shared_folders_table(shared_folders_list)
            
            # Display details for small result sets
            if len(shared_folders_list) < self.MAX_DETAILS_THRESHOLD and not skip_details:
                self._display_shared_folder_details(shared_folders_list, vault)

    def _display_shared_folders_table(self, shared_folders: Iterable[vault_types.SharedFolder]):
        """Display shared folders in a formatted table."""
        table = [[i + 1, sf.shared_folder_uid, sf.name] 
                for i, sf in enumerate(shared_folders)]
        report_utils.dump_report_data(
            table, headers=["#", 'Shared Folder UID', 'Name']
        )
        logger.info('')

    def _display_shared_folder_details(self, shared_folders: Iterable[vault_types.SharedFolder], 
                                     vault: vault_online.VaultOnline):
        """Display detailed information for shared folders."""
        get_command = RecordGetCommand()
        for sf in shared_folders:
            get_command._display_shared_folder_detail(vault=vault, uid=sf.shared_folder_uid)
    
    def _display_teams(self, teams: Iterable[vault_types.Team], skip_details: bool, 
                       vault: vault_online.VaultOnline):
        """Display teams in a formatted table with optional details."""
        teams_list = list(teams)
        
        teams_list.sort(key=lambda x: (x.name or ' ').lower())

        if teams_list:
            self._display_teams_table(teams_list)
            
            # Display details for small result sets
            if len(teams_list) < self.MAX_DETAILS_THRESHOLD and not skip_details:
                self._display_team_details(teams_list, vault)

    def _display_teams_table(self, teams: Iterable[vault_types.Team]):
        """Display teams in a formatted table."""
        table = [[i + 1, team.team_uid, team.name] 
                for i, team in enumerate(teams)]
        report_utils.dump_report_data(
            table, headers=["#", 'Team UID', 'Name']
        )
        logger.info('')

    def _display_team_details(self, teams: Iterable[vault_types.Team], vault: vault_online.VaultOnline):
        """Display detailed information for teams."""
        get_command = RecordGetCommand()
        for team in teams:
            get_command._display_team_detail(vault=vault, uid=team.team_uid)


class ClipboardCommand(base.ArgparseCommand):
    """Command to copy record data to clipboard or output to various destinations."""
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='clipboard-copy', 
            description='Retrieve the password for a specific record.'
        )
        self.add_arguments_to_parser(self.parser)
        super().__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add command line arguments to the parser."""
        parser.add_argument(
            '--username', 
            dest='username', 
            action='store', 
            help='match login name (optional)'
        )
        parser.add_argument(
            '--output', 
            dest='output', 
            choices=['clipboard', 'stdout', 'stdouthidden', 'variable'], 
            default='clipboard', 
            action='store',
            help='password output destination'
        )
        parser.add_argument(
            '--name', 
            dest='name', 
            action='store', 
            help='Variable name if output is set to variable'
        )
        parser.add_argument(
            '-cu', '--copy-uid', 
            dest='copy_uid', 
            action='store_true', 
            help='output uid instead of password'
        )
        parser.add_argument(
            '-l', '--login', 
            dest='login', 
            action='store_true', 
            help='output login name'
        )
        parser.add_argument(
            '-t', '--totp', 
            dest='totp', 
            action='store_true', 
            help='output totp code'
        )
        parser.add_argument(
            '--field', 
            dest='field', 
            action='store', 
            help='output custom field'
        )
        parser.add_argument(
            '-r', '--revision', 
            dest='revision', 
            type=int, 
            action='store',
            help='use a specific record revision'
        )
        parser.add_argument(
            'record', 
            nargs='?', 
            type=str, 
            action='store', 
            help='record path or UID'
        )

    def execute(self, context: KeeperParams, **kwargs):
        """Execute the clipboard copy command."""
        self._validate_vault(context)
        
        record_name = kwargs.get('record', '')
        if not record_name:
            self.get_parser().print_help()
            return

        user_pattern = self._create_user_pattern(kwargs.get('username'))
        record_uid = self._find_record_uid(context, record_name, user_pattern)
        
        if not record_uid:
            raise base.CommandError('', 'Enter name or uid of existing record')

        record = self._load_record_with_revision(context, record_uid, kwargs.get('revision'))
        if not record:
            logger.info(f'Record UID {record_uid} cannot be loaded.')
            return

        copy_item, text = self._extract_record_data(record, kwargs)
        if text:
            self._output_data(copy_item, text, kwargs, context, record_uid)

    def _validate_vault(self, context: KeeperParams):
        """Validate that vault is initialized."""
        if not context.vault:
            raise ValueError('Vault is not initialized. Login to initialize the vault.')

    def _create_user_pattern(self, username: Optional[str]) -> Optional[re.Pattern]:
        """Create regex pattern for username matching."""
        if not username:
            return None
        return re.compile(username, re.IGNORECASE)

    def _find_record_uid(self, context: KeeperParams, record_name: str, user_pattern: Optional[re.Pattern]) -> Optional[str]:
        """Find record UID by name or path."""
        
        if record_name in context.vault.vault_data._records:
            return record_name

        path_result = folder_utils.try_resolve_path(context, record_name)
        if path_result is not None:
            folder, record_name = path_result
            if folder and record_name:
                return self._find_record_in_folder(context, folder, record_name, user_pattern)

        return self._search_records_in_vault(context, record_name, user_pattern)

    def _find_record_in_folder(self, context: KeeperParams, folder, record_name: str, user_pattern: Optional[re.Pattern]) -> Optional[str]:
        """Find record in specific folder."""
        for folder_record_uid in folder.records:
            record = context.vault.vault_data.load_record(folder_record_uid)
            if not isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
                continue
            if record.title.lower() == record_name.lower():
                if self._matches_user_pattern(record, user_pattern):
                    return folder_record_uid
        return None

    def _search_records_in_vault(self, context: KeeperParams, record_name: str, user_pattern: Optional[re.Pattern]) -> Optional[str]:
        """Search for records in vault by name."""
        records = []
        for record in context.vault.vault_data.find_records(criteria=record_name):
            if isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
                if self._matches_user_pattern(record, user_pattern):
                    records.append(record)

        if len(records) == 0:
            raise base.CommandError('', 'Enter name or uid of existing record')
        elif len(records) > 1:
            records = self._filter_exact_matches(records, record_name)
            if len(records) > 1:
                raise base.CommandError('', f'More than one record are found for search criteria: {record_name}')

        if context.vault and 'output' in context.vault.__dict__ and context.vault.output == 'clipboard':
            logger.info('Record Title: %s', records[0].title)
        return records[0].record_uid

    def _filter_exact_matches(self, records: List, record_name: str) -> List:
        """Filter records to exact title matches."""
        try:
            pattern = re.compile(record_name, re.IGNORECASE).search
            exact_title = [x for x in records if pattern(x.title)]
            if len(exact_title) == 1:
                return exact_title
        except Exception:
            pass
        return records

    def _matches_user_pattern(self, record, user_pattern: Optional[re.Pattern]) -> bool:
        """Check if record matches user pattern."""
        if not user_pattern:
            return True
        
        login = self._get_record_login(record)
        return bool(login and user_pattern.match(login))

    def _get_record_login(self, record) -> str:
        """Extract login from record."""
        if isinstance(record, vault_record.PasswordRecord):
            return record.login
        elif isinstance(record, vault_record.TypedRecord):
            login_field = record.get_typed_field('login')
            if login_field is None:
                login_field = record.get_typed_field('email')
            if login_field:
                return login_field.get_default_value(str)
        return ''

    def _load_record_with_revision(self, context: KeeperParams, record_uid: str, revision: Optional[int]):
        """Load record with optional revision."""
        if revision is not None:
            history = self._load_record_history(context, record_uid)
            if not history:
                logger.info('Record does not have history of edit')
                return None
            
            length = len(history)
            if revision < 0:
                revision = length + revision
            if revision <= 0 or revision >= length:
                logger.info(f'Invalid revision {revision}: valid revisions 1..{length - 1}')
                return None
            
            revision_index = 0 if revision == 0 else length - revision
            return context.vault.vault_data.load_record(history[revision_index])
        else:
            return context.vault.vault_data.load_record(record_uid)

    def _extract_record_data(self, record, kwargs) -> tuple[str, str]:
        """Extract data from record based on command options."""
        if kwargs.get('copy_uid'):
            return 'Record UID', record.record_uid
        elif kwargs.get('login'):
            return 'Login', self._get_record_login(record)
        elif kwargs.get('totp'):
            return self._extract_totp_data(record)
        elif kwargs.get('field'):
            return self._extract_field_data(record, kwargs['field'])
        else:
            return self._extract_password_data(record)

    def _extract_totp_data(self, record) -> tuple[str, str]:
        """Extract TOTP data from record."""
        totp_url = None
        if isinstance(record, vault_record.PasswordRecord):
            totp_url = record.totp
        elif isinstance(record, vault_record.TypedRecord):
            totp_field = record.get_typed_field('oneTimeCode')
            if totp_field is None:
                totp_field = record.get_typed_field('otp')
            if totp_field:
                totp_url = totp_field.get_default_value(str)
        
        if totp_url:
            result = record_utils.get_totp_code(totp_url)
            if result:
                return 'TOTP Code', result[0]
        return 'TOTP Code', ''

    def _extract_field_data(self, record, field_name: str) -> tuple[str, str]:
        """Extract custom field data from record."""
        if field_name == 'notes':
            notes = record.notes if hasattr(record, 'notes') else ''
            return 'Notes', notes
        else:
            return self._extract_custom_field_data(record, field_name)

    def _extract_custom_field_data(self, record, field_name: str) -> tuple[str, str]:
        """Extract custom field data from record."""
        copy_item = f'Custom Field "{field_name}"'
        field_name, field_property = self._parse_field_name(field_name)
        
        if isinstance(record, vault_record.PasswordRecord):
            return copy_item, record.custom.get(field_name, '')
        elif isinstance(record, vault_record.TypedRecord):
            return self._extract_typed_field_data(record, field_name, field_property, copy_item)
        
        return copy_item, ''

    def _parse_field_name(self, field_name: str) -> tuple[str, str]:
        """Parse field name and property."""
        pre, sep, prop = field_name.rpartition(':')
        if sep == ':':
            return pre, prop
        return field_name, ''

    def _extract_typed_field_data(self, record, field_name: str, field_property: str, copy_item: str) -> tuple[str, str]:
        """Extract data from typed field."""
        field_type, sep, field_label = field_name.partition('.')
        rf = record_types.RecordFields.get(field_type)
        ft = record_types.FieldTypes.get(rf.type) if rf else None
        
        if ft is None:
            field_label = field_name
            field_type = 'text'
        
        field = record.get_typed_field(field_type, field_label)
        if not field:
            return copy_item, ''
        
        copy_item = f'Field "{field_name}"'
        
        if ft and field_property and isinstance(ft.value, dict):
            f_value = field.get_default_value(dict)
            if f_value:
                field_property = next(
                    (x for x in ft.value.keys() if x.lower().startswith(field_property.lower())), 
                    None
                )
                if field_property:
                    return copy_item, f_value.get(field_property, '')
                else:
                    return copy_item, json.dumps(f_value, indent=2)
        else:
            return copy_item, '\n'.join(field.get_external_value())

    def _extract_password_data(self, record) -> tuple[str, str]:
        """Extract password data from record."""
        if isinstance(record, vault_record.PasswordRecord):
            return 'Password', record.password
        elif isinstance(record, vault_record.TypedRecord):
            password_field = record.get_typed_field('password')
            if password_field:
                return 'Password', password_field.get_default_value(str)
        return 'Password', ''

    def _output_data(self, copy_item: str, text: str, kwargs: dict, context: KeeperParams, record_uid: str):
        """Output data to specified destination."""
        output_type = kwargs.get('output', 'clipboard')
        
        if output_type == 'clipboard':
            import pyperclip
            pyperclip.copy(text)
            logger.info(f'{copy_item} copied to clipboard')
        elif output_type == 'stdouthidden':
            logger.info(f'{Fore.RED}{Back.RED}{text}{Style.RESET_ALL}')
        elif output_type == 'variable':
            var_name = kwargs.get('name')
            if not var_name:
                raise base.CommandError('', '"name" parameter is required when "output" is set to "variable"')
            context.environment_variables[var_name] = text
            logger.info(f'{copy_item} is set to variable "{var_name}"')
        else:
            logger.info(text)
        
        # Schedule audit event for password copy
        if copy_item == 'Password' and text:
            context.vault.client_audit_event_plugin().schedule_audit_event('copy_password', record_uid=record_uid)

    def _load_record_history(self, context: KeeperParams, record_uid: str) -> Optional[list]:
        """Load record history from server."""
        if not context.vault:
            raise ValueError('Vault is not initialized. Login to initialize the vault.')
        
        current_rec = context.vault.vault_data._records[record_uid]
        record_key = current_rec.record_key

        request = {
            'command': 'get_record_history',
            'record_uid': record_uid,
            'client_time': utils.current_milli_time()
        }
        
        response = context.vault.keeper_auth.execute_auth_command(request)
        history = response['history']
        history.sort(key=lambda x: x.get('revision', 0), reverse=True)
        
        for rec in history:
            rec['record_key_unencrypted'] = record_key
            self._decrypt_history_record(rec, record_key)

        return history

    def _decrypt_history_record(self, rec: dict, record_key: bytes):
        """Decrypt history record data."""
        if 'data' in rec:
            data = utils.base64_url_decode(rec['data'])
            version = rec.get('version', 0)
            try:
                if version <= 2:
                    rec['data_unencrypted'] = crypto.decrypt_aes_v1(data, record_key)
                else:
                    rec['data_unencrypted'] = crypto.decrypt_aes_v2(data, record_key)
                
                if 'extra' in rec:
                    extra = utils.base64_url_decode(rec['extra'])
                    if version <= 2:
                        rec['extra_unencrypted'] = crypto.decrypt_aes_v1(extra, record_key)
                    else:
                        rec['extra_unencrypted'] = crypto.decrypt_aes_v2(extra, record_key)
            except Exception as e:
                logger.warning('Cannot decrypt record history revision: %s', e)


class RecordHistoryCommand(base.ArgparseCommand):
    """Command to show and manage record modification history."""

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='record-history', 
            parents=[base.report_output_parser],
            description='Show the history of a record modifications.'
        )
        self.add_arguments_to_parser(self.parser)
        super(RecordHistoryCommand, self).__init__(self.parser)
    
    @staticmethod
    def add_arguments_to_parser(parser: argparse.ArgumentParser):
        """Add command line arguments to the parser."""
        parser.add_argument(
            '-a', '--action', 
            dest='action', 
            choices=['list', 'diff', 'view', 'restore'], 
            action='store',
            help="filter by record history type. (default: 'list'). --revision required with 'restore' action."
        )
        parser.add_argument(
            '-r', '--revision', 
            dest='revision', 
            type=int, 
            action='store',
            help='only show the details for a specific revision.'
        )
        parser.add_argument(
            '-v', '--verbose', 
            dest='verbose', 
            action='store_true', 
            help="verbose output"
        )
        parser.add_argument(
            'record', 
            nargs='?', 
            type=str, 
            action='store', 
            help='record path or UID'
        )

    def execute(self, context: KeeperParams, **kwargs):
        """Execute the record history command."""
        self._validate_vault(context)

        vault = context.vault
        record_name = kwargs.get('record')
        if not record_name:
            self.get_parser().print_help()
            return

        record_uid = self._find_record_uid(context, record_name)
        if not record_uid:
            raise base.CommandError('history', 'Record not found: Enter name of existing record')

        history = self._load_record_history(vault, record_uid)
        if not history:
            logger.info('Record does not have history of edit')
            return

        action = kwargs.get('action') or 'list'
        self._execute_action(action, vault, history, kwargs)

    def _validate_vault(self, context: KeeperParams):
        """Validate that vault is initialized."""
        if not context.vault:
            raise ValueError('Vault is not initialized. Login to initialize the vault.')

    def _find_record_uid(self, context: KeeperParams, record_name: str) -> Optional[str]:
        """Find record UID by name or path."""
        
        vault = context.vault
        if record_name in vault.vault_data._records:
            return record_name

        path_result = folder_utils.try_resolve_path(context, record_name)
        if path_result is not None:
            folder, record_name = path_result
            if folder and record_name:
                return self._find_record_in_folder(vault, folder, record_name)

        return None

    def _find_record_in_folder(self, vault: vault_online.VaultOnline, folder, record_name: str) -> Optional[str]:
        """Find record in specific folder."""
        for folder_record_uid in folder.records:
            record = vault.vault_data.load_record(folder_record_uid)
            if record.title.lower() == record_name.lower():
                return folder_record_uid
        return None

    def _execute_action(self, action: str, vault: vault_online.VaultOnline, history: list, kwargs: dict):
        """Execute the specified history action."""
        if action == 'list':
            self._list_history(history, kwargs)
        elif action == 'view':
            self._view_revision(history, kwargs)
        elif action == 'diff':
            self._show_diff(history, kwargs)
        elif action == 'restore':
            self._restore_revision(vault, history, kwargs)

    def _list_history(self, history: list, kwargs: dict):
        """List record history revisions."""
        fmt = kwargs.get('format', '')
        headers = ['version', 'modified_by', 'time_modified']
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        
        rows = []
        length = len(history)
        for i, version in enumerate(history):
            dt = None
            if 'client_modified_time' in version:
                dt = datetime.datetime.fromtimestamp(int(version['client_modified_time'] / 1000.0))
            version_label = f'V.{length-i}' if i > 0 else 'Current'
            rows.append([version_label, version.get('user_name', ''), dt])
        
        return report_utils.dump_report_data(rows, headers, fmt=fmt, filename=kwargs.get('output'))

    def _view_revision(self, history: list, kwargs: dict):
        """View a specific revision."""
        revision = kwargs.get('revision') or 0
        length = len(history)
        
        if revision < 0 or revision >= length:
            raise ValueError(f'Invalid revision {revision}: valid revisions 1..{length - 1}')

        index = 0 if revision == 0 else length - revision
        rev = history[index]
        record_data_bytes = rev['data_unencrypted']
        record_data = json.loads(record_data_bytes)

        rows = []
        rows.append(['Title', record_data.get('title')])
        rows.append(['Type', record_data.get('type')])
        fields = record_data.get('fields', [])
        for field in fields:
            label = field.get('label')
            if not label or label == '':
                label = field.get('type')
            value = field.get('value')
            if value:
                if isinstance(value, list):
                    value = '\n'.join(value)
                rows.append([label, value])
        
        modified = datetime.datetime.fromtimestamp(int(rev['client_modified_time'] / 1000.0))
        rows.append(['Modified', modified])
        
        report_utils.dump_report_data(
            rows, 
            headers=['Name', 'Value'],
            title=f'Record Revision V.{revision}', 
            no_header=True, 
            right_align=(0,)
        )

    def _show_diff(self, history: list, kwargs: dict):
        """Show differences between revisions."""
        revision = kwargs.get('revision') or 0
        verbose = kwargs.get('verbose') or False
        length = len(history)
        
        if revision < 0 or revision >= length:
            raise ValueError(f'Invalid revision {revision}: valid revisions 1..{length - 1}')

        index = 0 if revision == 0 else length - revision
        rows = self._generate_diff_rows(history, index, length, verbose)
        
        headers = ('Version', 'Field', 'New Value', 'Old Value')
        report_utils.dump_report_data(rows, headers)

    def _generate_diff_rows(self, history: list, start_index: int, length: int, verbose: bool) -> list:
        """Generate diff rows between revisions."""
        count = 5
        current = history[start_index].get('data_unencrypted')
        current = json.loads(current)
        rows = []
        index = start_index
        
        while count >= 0 and current:
            previous = history[index + 1].get('data_unencrypted') if index < (length - 1) else None
            previous = json.loads(previous) if previous else None
            current_fields = self._get_record_fields(current)
            previous_fields = self._get_record_fields(previous) if previous else {}
            
            last_pos = len(rows)
            self._add_field_differences(rows, current_fields, previous_fields)
            
            version_label = 'Current' if index == 0 else f'V.{length - index}'
            if len(rows) > last_pos:
                rows[last_pos][0] = version_label
            else:
                rows.append([version_label, '', '', ''])
            
            count -= 1
            index += 1
            current = previous

        if not verbose:
            self._truncate_long_values(rows)
        
        return rows

    def _get_record_fields(self, record: dict) -> dict:
        """Get record fields as dictionary."""
        return_fields = {}
        return_fields['Title'] = record.get('title')
        for field in record.get('fields', []):
            name = field.get('label')
            if not name or name == '':
                name = field.get('type')
            value = field.get('value')
            if isinstance(value, list):
                value = '\n'.join(value)
            return_fields[name] = value                
        return return_fields

    def _add_field_differences(self, rows: list, current_fields: dict, previous_fields: dict):
        """Add field differences to rows."""
        for name, value in current_fields.items():
            if name in previous_fields:
                pre_value = previous_fields[name]
                if pre_value != value:
                    rows.append(['', name, value, pre_value])
                del previous_fields[name]
            else:
                if value:
                    rows.append(['', name, value, ''])
        
        for name, value in previous_fields.items():
            if value:
                if isinstance(value, list):
                    value = '\n'.join(value)
                rows.append(['', name, '', value])

    def _truncate_long_values(self, rows: list):
        """Truncate long values in diff rows for better readability."""
        for row in rows:
            for index in (2, 3):
                value = row[index]
                if not value:
                    continue
                lines = [x[:50]+'...' if len(x) > 52 else x for x in value.split('\n')]
                if len(lines) > 3:
                    lines = lines[:2]
                    lines.append('...')
                row[index] = '\n'.join(lines)

    def _restore_revision(self, vault: vault_online.VaultOnline, history: list, kwargs: dict):
        """Restore a specific revision."""
        revision = kwargs.get('revision') or 0
        length = len(history)
        
        if revision == 0:
            raise base.CommandError('history', f'Invalid revision to restore: Revisions: 1-{length - 1}')
        
        if revision < 0 or revision >= length:
            raise ValueError(f'Invalid revision {revision}: valid revisions 1..{length - 1}')

        index = 0 if revision == 0 else length - revision
        rev = history[index]
        record_data_bytes = rev['data_unencrypted']
        record_data = json.loads(record_data_bytes)

        self._execute_restore_request(vault, rev['record_uid'], rev['revision'])
        vault.client_audit_event_plugin().schedule_audit_event('revision_restored', record_uid=rev['record_uid'])
        vault.sync_down()
        logger.info('Record "%s" revision V.%d has been restored', record_data.get('title'), rev['revision'])

    def _execute_restore_request(self, vault: vault_online.VaultOnline, record_uid: str, revision: int):
        """Execute the restore request to server."""
        r_uid = utils.base64_url_decode(record_uid)
        roq = record_pb2.RecordRevert()
        roq.record_uid = r_uid
        roq.revert_to_revision = revision

        rq = record_pb2.RecordsRevertRequest()
        rq.records.append(roq)

        rs = vault.keeper_auth.execute_auth_rest(
            'vault/records_revert', 
            rq, 
            response_type=record_pb2.RecordsModifyResponse
        )

        ros = next((x for x in rs.records if x.record_uid == r_uid), None)
        if ros and ros.status != record_pb2.RS_SUCCESS:
            raise base.CommandError('history', f'Failed to restore record "{record_uid}": {ros.message}')

    @staticmethod
    def _load_record_history(vault: vault_online.VaultOnline, record_uid: str) -> Optional[list]:
        """Load record history from server."""
        current_rec = vault.vault_data._records[record_uid]
        record_key = current_rec.record_key

        request = {
            'command': 'get_record_history',
            'record_uid': record_uid,
            'client_time': utils.current_milli_time()
        }
        
        response = vault.keeper_auth.execute_auth_command(request)
        history = response['history']
        history.sort(key=lambda x: x.get('revision', 0), reverse=True)
        
        for rec in history:
            rec['record_key'] = record_key
            RecordHistoryCommand._decrypt_history_record(rec, record_key)

        return history

    @staticmethod
    def _decrypt_history_record(rec: dict, record_key: bytes):
        """Decrypt history record data."""
        if 'data' in rec:
            data = utils.base64_url_decode(rec['data'])
            version = rec.get('version', 0)
            try:
                if version <= 2:
                    rec['data_unencrypted'] = crypto.decrypt_aes_v1(data, record_key)
                else:
                    rec['data_unencrypted'] = crypto.decrypt_aes_v2(data, record_key)
                
                if 'extra' in rec:
                    extra = utils.base64_url_decode(rec['extra'])
                    if version <= 2:
                        rec['extra_unencrypted'] = crypto.decrypt_aes_v1(extra, record_key)
                    else:
                        rec['extra_unencrypted'] = crypto.decrypt_aes_v2(extra, record_key)
            except Exception as e:
                logger.warning('Cannot decrypt record history revision: %s', e)
