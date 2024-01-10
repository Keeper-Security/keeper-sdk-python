import enum
from typing import Dict, Union
from dataclasses import dataclass


@dataclass(frozen=True)
class FieldType:
    name: str
    value: Union[str, dict, int, bool]
    description: str


FieldTypes: Dict[str, FieldType] = {x.name: x for x in (
    FieldType('text', '', 'plain text'),
    FieldType('url', '', 'url string, can be clicked'),
    FieldType('multiline', '', 'multiline text'),
    FieldType('email', '', 'valid email address plus tag'),
    FieldType('secret', '', 'the field value is masked'),
    FieldType('otp', '', 'captures the seed, displays QR code'),
    FieldType('login', '', 'Login field, detected as the website login for browser extension or KFFA.'),
    FieldType('password', '', 'Field value is masked and allows for generation. Also complexity enforcements.'),
    FieldType('dropdown', '', 'list of text choices'),

    FieldType('date', 0, 'calendar date with validation, stored as unix milliseconds'),
    FieldType('checkbox', False, 'on/off checkbox'),

    FieldType('host', {'hostName': '', 'port': ''}, 'multiple fields to capture host information'),
    FieldType('phone', {'region': '', 'number': '', 'ext': '', 'type': ''}, 'numbers and symbols only plus tag'),
    FieldType('name', {'first': '', 'middle': '', 'last': ''}, 'multiple fields to capture name'),
    FieldType('address', {'street1': '', 'street2': '', 'city': '', 'state': '', 'zip': '', 'country': ''},
              'multiple fields to capture address'),
    FieldType('securityQuestion', {'question': '', 'answer': ''}, 'Security Question and Answer'),
    FieldType('paymentCard', {'cardNumber': '', 'cardExpirationDate': '', 'cardSecurityCode': ''},
              'Field consisting of validated card number, expiration date and security code.'),
    FieldType('bankAccount', {'accountType': '', 'routingNumber': '', 'accountNumber': ''},
              'bank account information'),
    FieldType('privateKey', {'publicKey': '', 'privateKey': ''},
              'private and/or public keys in ASN.1 format'),

    FieldType('fileRef', '', 'reference to the file field on another record'),
    FieldType('addressRef', '', 'reference to the address field on another record'),
    FieldType('cardRef', '', 'reference to the card record type'),
    FieldType('recordRef', '', 'reference to other record'),

    FieldType('pamResources', {'controllerUid': '', 'folderUid': '', 'resourceRef': []},
              'PAM resources'),
    FieldType('schedule', {'type': '', 'utcTime': '', 'month': '', }, 'schedule information'),
    FieldType('passkey', {'privateKey': {}, 'credentialId': '', 'signCount': 0, 'userId': '', 'relyingParty': '',
                          'username': '', 'createdDate': 0}, 'passwordless login passkey'),
    FieldType('script', {'fileRef': '', 'command': '', 'recordRef': [], }, 'Post rotation script'),
)}


class Multiple(enum.Enum):
    Never = 0
    Optional = 1
    Always = 2


@dataclass(frozen=True)
class RecordField:
    name: str
    type: str
    multiple: Multiple


RecordFields: Dict[str, RecordField] = {x.name: x for x in (
    RecordField('login', 'login', Multiple.Never),
    RecordField('password', 'secret', Multiple.Never),
    RecordField('company', 'text', Multiple.Never),
    RecordField('licenseNumber', 'multiline', Multiple.Never),
    RecordField('accountNumber', 'text', Multiple.Never),
    RecordField('bankAccount', 'bankAccount', Multiple.Never),
    RecordField('note', 'multiline', Multiple.Never),
    RecordField('oneTimeCode', 'otp', Multiple.Never),
    RecordField('keyPair', 'privateKey', Multiple.Never),
    RecordField('pinCode', 'secret', Multiple.Never),
    RecordField('expirationDate', 'date', Multiple.Never),
    RecordField('birthDate', 'date', Multiple.Never),
    RecordField('securityQuestion', 'securityQuestion', Multiple.Always),
    RecordField('fileRef', 'fileRef', Multiple.Always),

    RecordField('pamResources', 'pamResources', Multiple.Never),
    RecordField('pamHostname', 'host', Multiple.Never),
    RecordField('databaseType', 'dropdown', Multiple.Never),
    RecordField('directoryType', 'dropdown', Multiple.Never),

)}

for ft in FieldTypes.values():
    if ft.name not in RecordFields:
        RecordFields[ft.name] = RecordField(ft.name, ft.name, Multiple.Optional)
