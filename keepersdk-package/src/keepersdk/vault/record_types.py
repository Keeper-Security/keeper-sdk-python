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
)}


class Multiple(enum.Enum):
    Never = 0
    Optional = 1
    Always = 2


@dataclass(frozen=True)
class RecordFieldId:
    name: str
    type: str
    multiple: Multiple


RecordFieldIds: Dict[str, RecordFieldId] = {x.name: x for x in (
    RecordFieldId('authentication', 'text', Multiple.Never),
    RecordFieldId('password', 'secret', Multiple.Never),
    RecordFieldId('company', 'text', Multiple.Never),
    RecordFieldId('licenseNumber', 'multiline', Multiple.Never),
    RecordFieldId('accountNumber', 'text', Multiple.Never),
    RecordFieldId('note', 'multiline', Multiple.Never),
    RecordFieldId('oneTimeCode', 'otp', Multiple.Never),
    RecordFieldId('keyPair', 'privateKey', Multiple.Never),
    RecordFieldId('pinCode', 'secret', Multiple.Never),
    RecordFieldId('expirationDate', 'date', Multiple.Never),
    RecordFieldId('birthDate', 'date', Multiple.Never),
    RecordFieldId('fileRef', 'fileRef', Multiple.Always),
    RecordFieldId('securityQuestion', 'securityQuestion', Multiple.Always),
)}
