import calendar
import contextlib
import datetime
import getpass
import io
import json
import logging
from typing import Optional, List, Dict, Any, Iterable, Union, Iterator

import requests

from keepersdk.authentication import endpoint
from keepersdk.importer.import_data import (
    BaseImporter, Record, Folder, RecordField, RecordReferences, SharedFolder, Permission, BaseDownloadMembership,
    Team, Attachment, FIELD_TYPE_ONE_TIME_CODE)
from .lastpass_lib import fetcher, attachment, vault, attachment_reader, account, exceptions
from .lastpass_lib.parser import decode_aes256_base64_auto


class LastPassImporter(BaseImporter):
    month_names: Dict[str, int] = {}
    _months = ['', 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August',
               'September', 'October', 'November', 'December']
    for i in range(len(_months)):
        if _months[i]:
            month = _months[i].casefold()
            if month not in month_names:
                month_names[month] = i

    for i in range(len(calendar.month_name)):
        if calendar.month_name[i]:
            month = calendar.month_name[i].casefold()
            if month not in month_names:
                month_names[month] = i

    def __init__(self, username: str, password: str, totp_code: Optional[str] = None) -> None:
        super(LastPassImporter, self).__init__()

        self.vault: Optional[vault.Vault] = None
        self.addresses: List[LastPassAddress] = []
        self.username = username
        self.password = password
        self.totp_code = totp_code

    def cleanup(self) -> None:
        """Cleanup should be performed when finished with encrypted attachment files"""
        if self.vault:
            self.vault.cleanup()

    def vault_import(self, **kwargs) -> Iterable[Union[Record, SharedFolder]]:
        request_settings = {}
        if 'filter_folder' in kwargs and kwargs['filter_folder']:
            request_settings['filter_folder'] = kwargs['filter_folder']

        try:
            lastpass_vault = vault.Vault.open_remote(self.username, self.password, multifactor_password=self.totp_code, **request_settings)
        except exceptions.LastPassUnknownError as lpe:
            message = str(lpe)
            if message.startswith('Try again OR look for an email'):
                message += 'If you do not receive an email, go to LastPass > Account Settings > Advanced Settings ' \
                           'and ensure that "Disable Email Verification" is unchecked.'
            logging.warning(message)
            return
        else:
            self.vault = lastpass_vault
            if len(lastpass_vault.errors) > 0:
                err_list = '\n'.join(lastpass_vault.errors)
                logging.warning(f'The following errors occurred retrieving Lastpass shared folder members:\n{err_list}')

        for shared_folder in lastpass_vault.shared_folders:
            if shared_folder.name:
                folder = SharedFolder()
                folder.path = shared_folder.name

                folder.permissions = []
                if shared_folder.members:
                    for member in shared_folder.members:
                        perm = Permission()
                        perm.name = member['username']
                        perm.manage_records = member['readonly'] == '0'
                        perm.manage_users = member['can_administer'] == '1'
                        folder.permissions.append(perm)
                if shared_folder.teams:
                    for team in shared_folder.teams:
                        perm = Permission()
                        perm.name = team['name']
                        perm.manage_records = team['readonly'] == '0'
                        perm.manage_users = team['can_administer'] == '1'
                        folder.permissions.append(perm)

                yield folder

        account_attachments: Dict[str, List[attachment.LastpassAttachment]] = {}
        for atta in lastpass_vault.attachments:
            if not atta.parent_id:
                continue
            if atta.parent_id not in account_attachments:
                account_attachments[atta.parent_id] = []
            account_attachments[atta.parent_id].append(atta)

        missing_titles = 0
        lastpass_account: account.Account
        for lastpass_account in lastpass_vault.accounts:
            record = Record()
            is_secure_note = False
            if lastpass_account.url:
                record.login_url = lastpass_account.url.decode('utf-8', 'ignore')
                if record.login_url == 'http://sn':
                    is_secure_note = True
                    record.login_url = None
                elif record.login_url == 'http://group':
                    continue

            record.type = 'login'
            if lastpass_account.id:
                record.uid = lastpass_account.id
            if lastpass_account.name:
                record.title = lastpass_account.name.decode('utf-8', 'ignore')
            else:
                missing_titles += 1
                record.title = f'Missing Title {missing_titles}'
                logging.warning(f'Missing title in record from LastPass. Assigning title "{record.title}"')
            if lastpass_account.username:
                record.login = lastpass_account.username.decode('utf-8', 'ignore')
            if lastpass_account.password:
                record.password = lastpass_account.password.decode('utf-8', 'ignore')
            if lastpass_account.totp_url:
                record.fields.append(
                    RecordField.create(field_type=FIELD_TYPE_ONE_TIME_CODE, value=lastpass_account.totp_url)
                )
            if isinstance(lastpass_account.last_modified, int) and lastpass_account.last_modified > 0:
                record.last_modified = lastpass_account.last_modified
            if isinstance(lastpass_account.custom_fields, list):
                for cf in lastpass_account.custom_fields:
                    field_label = cf.name
                    if cf.type == 'password':
                        field_type = 'secret'
                    elif cf.type == 'email':
                        field_type = 'email'
                    elif cf.type == 'textarea':
                        field_type = 'multiline'
                    elif cf.type == 'tel':
                        field_type = 'phone'
                    else:
                        field_type = 'text'
                    rf = RecordField.create(field_type=field_type, field_label=field_label, value=cf.value)
                    record.fields.append(rf)

            if lastpass_account.attach_key and lastpass_account.id in account_attachments:
                record.attachments = []
                for atta in account_attachments[lastpass_account.id]:
                    shared_folder_id = ''
                    if lastpass_account.shared_folder:
                        shared_folder_id = lastpass_account.shared_folder.id
                    record.attachments.append(ImportLastPassAttachment(
                        attachment_info=atta, session_id=lastpass_vault.session.id,
                        attachment_key=lastpass_account.attach_key, shared_folder_id=shared_folder_id))

            if lastpass_account.notes:
                try:
                    notes = lastpass_account.notes.decode('utf-8', 'ignore')
                except UnicodeDecodeError:
                    notes = ''
                if notes.startswith('NoteType:'):
                    typed_values = self.parse_typed_notes(notes)
                    if 'NoteType' in typed_values:
                        note_type = typed_values.pop('NoteType', '')
                        notes = typed_values.pop('Notes', '')
                        typed_values.pop('Language', None)

                        if note_type == 'Bank Account':
                            self.populate_bank_account(record, typed_values)
                        elif note_type == 'Credit Card':
                            self.populate_credit_card(record, typed_values)
                        elif note_type == 'Address':
                            address = LastPassAddress.from_lastpass(typed_values)
                            if address:
                                addr_ref = self.append_address(address)
                                if addr_ref:
                                    record.uid = addr_ref
                                self.populate_address_only(record, address)
                                self.populate_address(record, typed_values)
                        elif note_type == 'Driver\'s License':
                            address_record = self.populate_driver_license(record, typed_values)
                            if address_record is not None:
                                yield address_record
                        elif note_type == 'Passport':
                            self.populate_passport(record, typed_values)
                        elif note_type == 'Social Security':
                            self.populate_ssn_card(record, typed_values)
                        elif note_type == 'Health Insurance' or note_type == 'Insurance':
                            self.populate_health_insurance(record, typed_values)
                        elif note_type == 'Membership':
                            self.populate_membership(record, typed_values)
                        elif note_type == 'Database':
                            self.populate_database(record, typed_values)
                        elif note_type == 'Server':
                            self.populate_server(record, typed_values)
                        elif note_type == 'SSH Key':
                            self.populate_ssh_key(record, typed_values)
                        elif note_type == 'Software License':
                            self.populate_software_license(record, typed_values)

                    username_value = typed_values.pop('Username', '')
                    if username_value:
                        if record.login:
                            if record.login != username_value:
                                rf = RecordField.create(field_label='Username', value=username_value)
                                if record.type:
                                    rf.type = 'login'
                                record.fields.append(rf)
                        else:
                            record.login = username_value

                    password_value = typed_values.pop('Password', '')
                    if password_value:
                        if record.password:
                            if record.password != password_value:
                                rf = RecordField.create(field_label='Password', value=password_value)
                                if record.type:
                                    rf.type = 'password'
                                record.fields.append(rf)
                        else:
                            record.password = password_value

                    url_value = typed_values.pop('URL', '')
                    if url_value:
                        if record.login_url:
                            if record.login_url != url_value:
                                rf = RecordField.create(field_label='URL', value=url_value)
                                if record.type:
                                    rf.type = 'url'
                                record.fields.append(rf)
                        else:
                            record.login_url = url_value

                    for key in typed_values:
                        value = typed_values[key]
                        if value:
                            if record.type:
                                rf = RecordField.create(field_type='text', field_label=key, value=str(value))
                            else:
                                rf = RecordField.create(field_label=key, value=str(value))
                            record.fields.append(rf)
                else:
                    if is_secure_note and not record.login and not record.password:
                        record.type = 'encryptedNotes'
                        rf = RecordField.create(field_type='note', value=notes)
                        record.fields.append(rf)
                        notes = ''
                    else:
                        if record.login_url == 'http://':
                            record.login_url = ''

                record.notes = notes

            if lastpass_account.group or lastpass_account.shared_folder:
                fol = Folder()
                if lastpass_account.shared_folder:
                    fol.domain = lastpass_account.shared_folder.name
                if lastpass_account.group:
                    fol.path = lastpass_account.group
                    if isinstance(fol.path, bytes):
                        fol.path = fol.path.decode('utf-8', 'ignore')
                record.folders = [fol]

            yield record

    def description(self) -> str:
        return 'lastpass_lib'

    @staticmethod
    def card_expiration(from_lastpass: str) -> str:
        if from_lastpass:
            comp = [x.strip().casefold() for x in from_lastpass.split(',')]
            if len(comp) == 2 and all(comp):
                try:
                    year = int(comp[1])
                    if year < 200:
                        year += 2000
                        comp[1] = str(year)
                except ValueError:
                    pass
                if comp[0] in LastPassImporter.month_names:
                    return f'{LastPassImporter.month_names[comp[0]]:0>2}/{comp[1]}'
        return from_lastpass

    @staticmethod
    def lastpass_date(from_lastpass: Optional[str]) -> int:
        if from_lastpass:
            comp = [x.strip().casefold() for x in from_lastpass.split(',')]
            if len(comp) == 3 and all(comp):
                try:
                    month = LastPassImporter.month_names[comp[0]]
                    day = int(comp[1])
                    year = int(comp[2])
                    dt = datetime.date(year, month, day)
                    return int(datetime.datetime.combine(dt, datetime.time.min).timestamp() * 1000)
                except Exception:
                    pass
        return -1

    def find_address(self, address: 'LastPassAddress') -> Optional[int]:
        for i in range(len(self.addresses)):
            if self.addresses[i] == address:
                return i + 1

    def append_address(self, address: 'LastPassAddress') -> Optional[int]:
        if isinstance(address, LastPassAddress):
            self.addresses.append(address)
            return len(self.addresses)

    @staticmethod
    def parse_typed_notes(notes: str) -> Dict[str, Any]:
        lines = notes.split('\n')
        fields = {}
        key = ''
        value = ''
        for line in lines:
            k, s, v = line.partition(':')
            if s == ':':
                if key:
                    if key == 'Notes':
                        value += line
                    elif key == 'Private Key':
                        if k == 'Public Key':
                            fields[key] = value
                            key = k
                            value = v
                        else:
                            value += '\n' + line
                    else:
                        fields[key] = value
                        key = k
                        value = v
                else:
                    key = k
                    value = v
            else:
                if key:
                    value += '\n' + line
        if key:
            fields[key] = value
        return fields

    @staticmethod
    def populate_address(record, notes):  # type: (Record, dict) -> None
        person = LastPassPersonName()
        person.first = notes.pop('First Name', '')
        person.middle = notes.pop('Middle Name', '')
        person.last = notes.pop('Last Name', '')

        if person.first or person.last:
            pf = RecordField.create(field_type='name')
            pf.value = {
                'first': person.first,
                'middle': person.middle,
                'last': person.last
            }
            record.fields.append(pf)

        dt = LastPassImporter.lastpass_date(notes.pop('Birthday', None))
        if dt != -1:
            dtf = RecordField.create(field_type='birthDate', value=dt)
            record.fields.append(dtf)

        email = notes.pop('Email Address', None)
        if email:
            dtf = RecordField.create(field_type='email', value=email)
            record.fields.append(dtf)
        for phone_type in ['Phone', 'Evening Phone', 'Mobile Phone', 'Fax']:
            phone = notes.pop(phone_type, '')
            if phone:
                try:
                    phone_dict = json.loads(phone)
                    if isinstance(phone_dict, dict):
                        if 'num' in phone_dict:
                            phone_number = phone_dict['num']
                            phone_ext = phone_dict.get('ext') or ''
                            _ = phone_dict.get('cc3l') or ''
                            phf = RecordField.create(field_type='phone', field_label=phone_type)
                            phf.value = {
                              #  'region': phone_country_code,
                                'number': phone_number,
                                'ext': phone_ext,
                                'type': ('Mobile' if phone_type.startswith('Mobile') else
                                         'Home' if phone_type.startswith('Evening') else
                                         'Work')
                            }
                            record.fields.append(phf)
                except Exception:
                    pass

    @staticmethod
    def populate_address_only(record: Record, lastpass_address: 'LastPassAddress') -> None:
        if lastpass_address:
            record.type = 'address'
            address = RecordField.create(field_type='address')
            address.value = {
                'street1': lastpass_address.street1 or '',
                'street2': lastpass_address.street2 or '',
                'city': lastpass_address.city or '',
                'state': lastpass_address.state or '',
                'zip': lastpass_address.zip or '',
                'country': lastpass_address.country or '',
            }
            record.fields.append(address)

    def populate_credit_card(self, record: Record, notes: Dict[str, Any]) -> None:
        record.type = 'bankCard'
        card = RecordField.create(field_type='paymentCard')
        card.value = {
            'cardNumber': notes.pop('Number', ''),
            'cardExpirationDate': self.card_expiration(notes.pop('Expiration Date', '')),
            'cardSecurityCode': notes.pop('Security Code', '')
        }
        record.fields.append(card)
        card_holder = RecordField.create(field_type='text', field_label='cardholderName', value=notes.pop('Name on Card', ''))
        record.fields.append(card_holder)

        dt = self.lastpass_date(notes.pop('Start Date', ''))
        if dt != -1:
            dtf = RecordField.create(field_type='date', field_label='Start Date', value=dt)
            record.fields.append(dtf)


    @staticmethod
    def populate_bank_account(record: Record, notes: Dict[str, Any]) -> None:
        record.type = 'bankAccount'
        bank = RecordField.create(field_type='bankAccount')
        bank.value = {
            'accountType': notes.pop('Account Type', ''),
            'routingNumber': notes.pop('Routing Number', ''),
            'accountNumber': notes.pop('Account Number', ''),
        }
        record.fields.append(bank)

    @staticmethod
    def populate_passport(record: Record, notes: Dict[str, Any]) -> None:
        record.type = 'passport'
        number = RecordField.create(field_type='accountNumber',
                                    field_label='passportNumber',
                                    value=notes.pop('Number', ''))
        record.fields.append(number)
        person = LastPassPersonName.from_lastpass(notes.pop('Name', None))
        if person:
            pf = RecordField.create(field_type='name')
            pf.value = {
                'first': person.first,
                'middle': person.middle,
                'last': person.last
            }
            record.fields.append(pf)
        dt = LastPassImporter.lastpass_date(notes.pop('Date of Birth', None))
        if dt != -1:
            dtf = RecordField.create(field_type='birthDate', value=dt)
            record.fields.append(dtf)
        dt = LastPassImporter.lastpass_date(notes.pop('Expiration Date', None))
        if dt != -1:
            dtf = RecordField.create(field_type='expirationDate', value=dt)
            record.fields.append(dtf)
        dt = LastPassImporter.lastpass_date(notes.pop('Issued Date', None))
        if dt != -1:
            dtf = RecordField.create(field_type='date', field_label='dateIssued', value=dt)
            record.fields.append(dtf)

    def populate_driver_license(self, record: Record, notes: Dict[str, Any]) -> Optional[Record]:
        record.type = 'driverLicense'
        account_number = RecordField.create(field_type='accountNumber', field_label='dlNumber', value=notes.pop('Number', ''))
        record.fields.append(account_number)
        dt = LastPassImporter.lastpass_date(notes.pop('Expiration Date', None))
        if dt != -1:
            dtf = RecordField.create(field_type='expirationDate', value=dt)
            record.fields.append(dtf)
        dt = LastPassImporter.lastpass_date(notes.pop('Date of Birth', None))
        if dt != -1:
            dtf = RecordField.create(field_type='birthDate', value=dt)
            record.fields.append(dtf)
        person = LastPassPersonName.from_lastpass(notes.pop('Name', None))
        if person:
            pf = RecordField.create(field_type='name')
            pf.value = {
                'first': person.first,
                'middle': person.middle,
                'last': person.last
            }
            record.fields.append(pf)
        address = LastPassAddress.from_lastpass(notes)
        address_record = None
        if address:
            ref_no = self.find_address(address)
            if ref_no:
                if record.references is None:
                    record.references = []
                address_ref = next((x for x in record.references if x.type == 'address'), None)
                if address_ref is None:
                    address_ref = RecordReferences()
                    address_ref.type = 'address'
                    record.references.append(address_ref)
                address_ref.uids.append(ref_no)
        return address_record

    @staticmethod
    def populate_ssn_card(record: Record, notes: Dict[str, Any]) -> None:
        record.type = 'ssnCard'
        number = RecordField.create(field_type='accountNumber', field_label='identityNumber', value=notes.pop('Number', None))
        record.fields.append(number)
        person = LastPassPersonName.from_lastpass(notes.pop('Name', None))
        if person:
            pf = RecordField.create(field_type='name')
            pf.value = {
                'first': person.first,
                'middle': person.middle,
                'last': person.last
            }
            record.fields.append(pf)

    @staticmethod
    def populate_health_insurance(record: Record, notes: Dict[str, Any]) -> None:
        record.type = 'healthInsurance'
        number = RecordField.create(field_type='accountNumber', value=notes.pop('Policy Number', None))
        record.fields.append(number)
        dt = LastPassImporter.lastpass_date(notes.pop('Expiration', None))
        if dt != -1:
            dtf = RecordField.create(field_type='date', field_label='Expiration', value=dt)
            record.fields.append(dtf)

    @staticmethod
    def populate_membership(record: Record, notes: Dict[str, Any]) -> None:
        record.type = 'membership'
        number = RecordField.create(field_type='accountNumber', value=notes.pop('Membership Number', None))
        record.fields.append(number)
        person = LastPassPersonName.from_lastpass(notes.pop('Member Name', None))
        if person:
            pf = RecordField.create(field_type='name')
            pf.value = {
                'first': person.first,
                'middle': person.middle,
                'last': person.last
            }
            record.fields.append(pf)
        dt = LastPassImporter.lastpass_date(notes.pop('Start Date', None))
        if dt != -1:
            dtf = RecordField.create(field_type='date', field_label='Start Date', value=dt)
            record.fields.append(dtf)
        dt = LastPassImporter.lastpass_date(notes.pop('Expiration Date', None))
        if dt != -1:
            dtf = RecordField.create(field_type='date', field_label='Expiration Date', value=dt)
            record.fields.append(dtf)

    @staticmethod
    def populate_database(record: Record, notes: Dict[str, Any]) -> None:
        record.type = 'databaseCredentials'
        db_type = RecordField.create(field_type='text', field_label='type', value=notes.pop('Type', None))
        record.fields.append(db_type)

        host = RecordField.create(field_type='host')
        host.value = {
            'hostName': notes.pop('Hostname', ''),
            'port': notes.pop('Port', ''),
        }
        record.fields.append(host)
        record.login_url = ''

    @staticmethod
    def populate_server(record: Record, notes: Dict[str, Any]):
        record.type = 'serverCredentials'
        host = RecordField.create(field_type='host')
        host.value = {
            'hostName': notes.pop('Hostname', ''),
            'port': notes.pop('Port', ''),
        }
        record.fields.append(host)

    @staticmethod
    def populate_ssh_key(record: Record, notes: Dict[str, Any]) -> None:
        record.type = 'sshKeys'
        passphrase = notes.pop('Passphrase', None)
        if passphrase:
            if record.password:
                if record.password != passphrase:
                    passphrase = RecordField.create(field_type='password', field_label='passphrase', value=passphrase)
                    record.fields.append(passphrase)
            else:
                record.password = passphrase
        host = RecordField.create(field_type='host')
        host.value = {
            'hostName': notes.pop('Hostname', ''),
            'port': notes.pop('Port', ''),
        }
        record.fields.append(host)
        private_key = notes.pop('Private Key', None)
        public_key = notes.pop('Public Key', None)
        if private_key or public_key:
            value = {
                'privateKey': private_key,
                'publicKey': public_key
            }
            pk = RecordField.create(field_type='keyPair', value=value)
            record.fields.append(pk)

        dt = LastPassImporter.lastpass_date(notes.pop('Date', None))
        if dt != -1:
            dtf = RecordField.create(field_type='date', value=dt)
            record.fields.append(dtf)

    @staticmethod
    def populate_software_license(record: Record, notes: Dict[str, Any]) -> None:
        record.type = 'softwareLicense'
        number = RecordField.create(field_type='licenseNumber', value=notes.pop('License Key', None))
        record.fields.append(number)
        dt = LastPassImporter.lastpass_date(notes.pop('Purchase Date', None))
        if dt != -1:
            dtf = RecordField.create(field_type='date', field_label='dateActive', value=dt)
            record.fields.append(dtf)


class LastPassPersonName(object):
    def __init__(self):
        self.first = ''
        self.middle = ''
        self.last = ''

    @staticmethod
    def from_lastpass(name: Optional[str]) -> Optional['LastPassPersonName']:
        if not name:
            return None
        if not isinstance(name, str):
            return None
        person = LastPassPersonName()
        last, sep, other = name.partition(',')
        if sep == ',':
            person.last = last.strip()
            comps = [x for x in other.strip().split(' ') if x]
        else:
            comps = [x for x in name.split(' ') if x]
            person.last = comps.pop(-1)
        if len(comps) > 0:
            person.first = comps.pop(0)
        if len(comps) > 0:
            person.middle = ' '.join(comps)

        if not person.first and not person.last:
            return None

        return person


class LastPassAddress(object):
    def __init__(self):
        self.street1 = ''
        self.street2 = ''
        self.city = ''
        self.state = ''
        self.zip = ''
        self.country = ''

    @staticmethod
    def _compare_case_insensitive(s1: Optional[str], s2: Optional[str]) -> bool:
        if isinstance(s1, str) and isinstance(s2, str):
            return s1.casefold() == s2.casefold()
        if s1 is None and s2 is None:
            return True
        return False

    def __eq__(self, other):
        if not isinstance(other, LastPassAddress):
            return False
        return (self._compare_case_insensitive(self.street1, other.street1) and
                self._compare_case_insensitive(self.street2, other.street2) and
                self._compare_case_insensitive(self.city, other.city) and
                self._compare_case_insensitive(self.state, other.state))

    @staticmethod
    def from_lastpass(notes: Dict[str, Any]) -> Optional['LastPassAddress']:
        if not isinstance(notes, dict):
            return None

        address = LastPassAddress()
        if 'Address 1' in notes:
            address.street1 = notes.pop('Address 1', '')
            address.street2 = notes.pop('Address 2', '')
        elif 'Address' in notes:
            s1, sep, s2 = notes.pop('Address', '').partition(',')
            address.street1 = s1.strip()
            if sep == ',':
                address.street2 = s2.strip()
        else:
            return None

        address.city = notes.pop('City / Town', '')
        address.state = notes.pop('State', '')
        address.zip = notes.pop('Zip / Postal Code', '')
        address.country = notes.pop('Country', '')

        return address


class LastpassMembershipDownload(BaseDownloadMembership):
    def download_membership(self, folders_only: Optional[bool]=False, **kwargs) -> Iterable[Union[SharedFolder, Team]]:
        username = input('...' + 'LastPass Username'.rjust(30) + ': ')
        if not username:
            logging.warning('LastPass username is required')
            return
        password = getpass.getpass(prompt='...' + 'LastPass Password'.rjust(30) + ': ', stream=None)
        if not password:
            logging.warning('LastPass password is required')
            return

        print('Press <Enter> if account is not protected with Multi-factor Authentication')
        twofa_code: Optional[str] = getpass.getpass(prompt='...' + 'Multi-factor Password'.rjust(30) + ': ', stream=None)
        if not twofa_code:
            twofa_code = None

        session = None
        try:
            session = fetcher.login(username, password, twofa_code)
            blob = fetcher.fetch(session)
            encryption_key = blob.encryption_key(username, password)
            lastpass_vault = vault.Vault(blob, encryption_key, session, shared_folder_details=False)

            lastpass_shared_folder = [x for x in lastpass_vault.shared_folders]

            for lpsf in lastpass_shared_folder:
                logging.info('Loading shared folder membership for "%s"', lpsf.name)

                members, teams, error = fetcher.fetch_shared_folder_members(session, lpsf.id)
                sf = SharedFolder()
                sf.uid = lpsf.id
                sf.path = lpsf.name
                sf.permissions = []
                if members:
                    sf.permissions.extend((self._lastpass_permission(x) for x in members))
                if teams:
                    sf.permissions.extend((self._lastpass_permission(x, team=True) for x in teams))
                yield sf

        except Exception as e:
            logging.warning(e)
        finally:
            if session:
                fetcher.logout(session)

    @staticmethod
    def _lastpass_permission(lp_permission: Dict[str, Any], team: Optional[bool] = False) -> Permission:
        permission = Permission()
        if team:
            permission.name = lp_permission['name']
        else:
            permission.name = lp_permission['username']
        permission.manage_records = lp_permission['readonly'] == '0'
        permission.manage_users = lp_permission['can_administer'] == '1'
        return permission


class _LastpassStream(io.RawIOBase):
    def __init__(self, stream, encryption_key: bytes):
        self.generator: Optional[Iterator[bytes]] = attachment_reader.decode_aes256_base64_from_stream(stream, encryption_key)
        self.tail: Optional[bytes] = None

    def readinto(self, buffer) -> int:
        written = 0
        while self.generator is not None and written < len(buffer):
            if isinstance(self.tail, bytes):
                to_write = min(len(self.tail), len(buffer) - written)
                buffer[written:written+to_write] = self.tail[0:to_write]
                written += to_write
                self.tail = self.tail[to_write:]
                if len(self.tail) > 0:
                    break
            try:
                self.tail = next(self.generator)
            except StopIteration:
                self.generator = None
        return written


class ImportLastPassAttachment(Attachment):
    def __init__(self, attachment_info: attachment.LastpassAttachment, attachment_key: bytes, session_id: str,
                 shared_folder_id: Optional[str] = None) -> None:
        super().__init__()
        self.file_uid = attachment_info.file_id
        self.name = decode_aes256_base64_auto(attachment_info.encrypted_filename, attachment_key).decode('utf-8')
        self.size = (attachment_info.lastpass_size-42)*9//16 if attachment_info.lastpass_size > 42 else 1
        self.mime = attachment_info.mime

        self.shared_folder_id = shared_folder_id
        self.encrypted_name = attachment_info.encrypted_filename
        self.storagekey = attachment_info.storagekey
        self.session_id = session_id
        self.attachment_key = attachment_key

    @contextlib.contextmanager
    def open(self):
        url = f'{fetcher.https_host}/getattach.php'
        data = {'getattach': self.storagekey}
        if self.shared_folder_id:
            data['sharedfolderid'] = self.shared_folder_id

        with requests.post(url, data=data, cookies={'PHPSESSID': self.session_id}, proxies=endpoint.get_proxies(),
                           verify=endpoint.get_certificate_check(), stream=True) as response:
            if response.status_code == requests.codes.ok:
                yield _LastpassStream(response.raw, self.attachment_key)
            else:
                raise Exception(
                    f'Attachment {self.name} failed to download: HTTP {response.status_code}, {response.reason}')
