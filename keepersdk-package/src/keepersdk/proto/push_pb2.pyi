from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MessageType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    UNKNOWN: _ClassVar[MessageType]
    DNA: _ClassVar[MessageType]
    SSO: _ClassVar[MessageType]
    CHAT: _ClassVar[MessageType]
    USER: _ClassVar[MessageType]
    ENTERPRISE: _ClassVar[MessageType]
    KEEPER: _ClassVar[MessageType]
    SESSION: _ClassVar[MessageType]
    DEVICE: _ClassVar[MessageType]
    TOTP: _ClassVar[MessageType]
UNKNOWN: MessageType
DNA: MessageType
SSO: MessageType
CHAT: MessageType
USER: MessageType
ENTERPRISE: MessageType
KEEPER: MessageType
SESSION: MessageType
DEVICE: MessageType
TOTP: MessageType

class UserRegistrationRequest(_message.Message):
    __slots__ = ["messageSessionUid", "userId", "enterpriseId"]
    MESSAGESESSIONUID_FIELD_NUMBER: _ClassVar[int]
    USERID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    messageSessionUid: bytes
    userId: int
    enterpriseId: int
    def __init__(self, messageSessionUid: _Optional[bytes] = ..., userId: _Optional[int] = ..., enterpriseId: _Optional[int] = ...) -> None: ...

class KAToPushServerRequest(_message.Message):
    __slots__ = ["messageType", "message", "messageSessionUid", "encryptedDeviceToken", "userId", "enterpriseId"]
    MESSAGETYPE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    MESSAGESESSIONUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    USERID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    messageType: MessageType
    message: str
    messageSessionUid: bytes
    encryptedDeviceToken: _containers.RepeatedScalarFieldContainer[bytes]
    userId: _containers.RepeatedScalarFieldContainer[int]
    enterpriseId: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, messageType: _Optional[_Union[MessageType, str]] = ..., message: _Optional[str] = ..., messageSessionUid: _Optional[bytes] = ..., encryptedDeviceToken: _Optional[_Iterable[bytes]] = ..., userId: _Optional[_Iterable[int]] = ..., enterpriseId: _Optional[_Iterable[int]] = ...) -> None: ...

class WssConnectionRequest(_message.Message):
    __slots__ = ["messageSessionUid", "encryptedDeviceToken", "deviceTimeStamp"]
    MESSAGESESSIONUID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    DEVICETIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    messageSessionUid: bytes
    encryptedDeviceToken: bytes
    deviceTimeStamp: int
    def __init__(self, messageSessionUid: _Optional[bytes] = ..., encryptedDeviceToken: _Optional[bytes] = ..., deviceTimeStamp: _Optional[int] = ...) -> None: ...

class WssClientResponse(_message.Message):
    __slots__ = ["messageType", "message"]
    MESSAGETYPE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    messageType: MessageType
    message: str
    def __init__(self, messageType: _Optional[_Union[MessageType, str]] = ..., message: _Optional[str] = ...) -> None: ...

class PushServerDeviceRegistrationRequest(_message.Message):
    __slots__ = ["encryptedDeviceToken", "pushToken", "mobilePushPlatform", "transmissionKey"]
    ENCRYPTEDDEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    PUSHTOKEN_FIELD_NUMBER: _ClassVar[int]
    MOBILEPUSHPLATFORM_FIELD_NUMBER: _ClassVar[int]
    TRANSMISSIONKEY_FIELD_NUMBER: _ClassVar[int]
    encryptedDeviceToken: bytes
    pushToken: str
    mobilePushPlatform: str
    transmissionKey: bytes
    def __init__(self, encryptedDeviceToken: _Optional[bytes] = ..., pushToken: _Optional[str] = ..., mobilePushPlatform: _Optional[str] = ..., transmissionKey: _Optional[bytes] = ...) -> None: ...

class SnsMessage(_message.Message):
    __slots__ = ["messageType", "message"]
    MESSAGETYPE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    messageType: MessageType
    message: bytes
    def __init__(self, messageType: _Optional[_Union[MessageType, str]] = ..., message: _Optional[bytes] = ...) -> None: ...
