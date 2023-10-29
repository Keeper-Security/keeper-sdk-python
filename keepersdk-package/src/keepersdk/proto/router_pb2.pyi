import pam_pb2 as _pam_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RouterResponseCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    RRC_OK: _ClassVar[RouterResponseCode]
    RRC_GENERAL_ERROR: _ClassVar[RouterResponseCode]
    RRC_NOT_ALLOWED: _ClassVar[RouterResponseCode]
    RRC_BAD_REQUEST: _ClassVar[RouterResponseCode]
    RRC_TIMEOUT: _ClassVar[RouterResponseCode]
    RRC_BAD_STATE: _ClassVar[RouterResponseCode]
    RRC_CONTROLLER_DOWN: _ClassVar[RouterResponseCode]
    RRC_WRONG_INSTANCE: _ClassVar[RouterResponseCode]

class RouterRotationStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    RRS_ONLINE: _ClassVar[RouterRotationStatus]
    RRS_NO_ROTATION: _ClassVar[RouterRotationStatus]
    RRS_NO_CONTROLLER: _ClassVar[RouterRotationStatus]
    RRS_CONTROLLER_DOWN: _ClassVar[RouterRotationStatus]
RRC_OK: RouterResponseCode
RRC_GENERAL_ERROR: RouterResponseCode
RRC_NOT_ALLOWED: RouterResponseCode
RRC_BAD_REQUEST: RouterResponseCode
RRC_TIMEOUT: RouterResponseCode
RRC_BAD_STATE: RouterResponseCode
RRC_CONTROLLER_DOWN: RouterResponseCode
RRC_WRONG_INSTANCE: RouterResponseCode
RRS_ONLINE: RouterRotationStatus
RRS_NO_ROTATION: RouterRotationStatus
RRS_NO_CONTROLLER: RouterRotationStatus
RRS_CONTROLLER_DOWN: RouterRotationStatus

class RouterResponse(_message.Message):
    __slots__ = ["responseCode", "errorMessage", "encryptedPayload"]
    RESPONSECODE_FIELD_NUMBER: _ClassVar[int]
    ERRORMESSAGE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDPAYLOAD_FIELD_NUMBER: _ClassVar[int]
    responseCode: RouterResponseCode
    errorMessage: str
    encryptedPayload: bytes
    def __init__(self, responseCode: _Optional[_Union[RouterResponseCode, str]] = ..., errorMessage: _Optional[str] = ..., encryptedPayload: _Optional[bytes] = ...) -> None: ...

class RouterControllerMessage(_message.Message):
    __slots__ = ["messageType", "messageUid", "controllerUid", "streamResponse", "payload", "timeout"]
    MESSAGETYPE_FIELD_NUMBER: _ClassVar[int]
    MESSAGEUID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    STREAMRESPONSE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    messageType: _pam_pb2.ControllerMessageType
    messageUid: bytes
    controllerUid: bytes
    streamResponse: bool
    payload: bytes
    timeout: int
    def __init__(self, messageType: _Optional[_Union[_pam_pb2.ControllerMessageType, str]] = ..., messageUid: _Optional[bytes] = ..., controllerUid: _Optional[bytes] = ..., streamResponse: bool = ..., payload: _Optional[bytes] = ..., timeout: _Optional[int] = ...) -> None: ...

class RouterUserAuth(_message.Message):
    __slots__ = ["transmissionKey", "sessionToken", "userId", "enterpriseUserId", "deviceName", "deviceToken"]
    TRANSMISSIONKEY_FIELD_NUMBER: _ClassVar[int]
    SESSIONTOKEN_FIELD_NUMBER: _ClassVar[int]
    USERID_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    DEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    transmissionKey: bytes
    sessionToken: bytes
    userId: int
    enterpriseUserId: int
    deviceName: str
    deviceToken: bytes
    def __init__(self, transmissionKey: _Optional[bytes] = ..., sessionToken: _Optional[bytes] = ..., userId: _Optional[int] = ..., enterpriseUserId: _Optional[int] = ..., deviceName: _Optional[str] = ..., deviceToken: _Optional[bytes] = ...) -> None: ...

class RouterDeviceAuth(_message.Message):
    __slots__ = ["clientId", "clientVersion", "signature", "enterpriseId", "nodeId", "deviceName", "deviceToken", "controllerName", "controllerUid", "ownerUser"]
    CLIENTID_FIELD_NUMBER: _ClassVar[int]
    CLIENTVERSION_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    DEVICENAME_FIELD_NUMBER: _ClassVar[int]
    DEVICETOKEN_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERNAME_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    OWNERUSER_FIELD_NUMBER: _ClassVar[int]
    clientId: str
    clientVersion: str
    signature: bytes
    enterpriseId: int
    nodeId: int
    deviceName: str
    deviceToken: bytes
    controllerName: str
    controllerUid: bytes
    ownerUser: str
    def __init__(self, clientId: _Optional[str] = ..., clientVersion: _Optional[str] = ..., signature: _Optional[bytes] = ..., enterpriseId: _Optional[int] = ..., nodeId: _Optional[int] = ..., deviceName: _Optional[str] = ..., deviceToken: _Optional[bytes] = ..., controllerName: _Optional[str] = ..., controllerUid: _Optional[bytes] = ..., ownerUser: _Optional[str] = ...) -> None: ...

class RouterRecordRotation(_message.Message):
    __slots__ = ["recordUid", "configurationUid", "controllerUid", "resourceUid", "noSchedule"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATIONUID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    RESOURCEUID_FIELD_NUMBER: _ClassVar[int]
    NOSCHEDULE_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    configurationUid: bytes
    controllerUid: bytes
    resourceUid: bytes
    noSchedule: bool
    def __init__(self, recordUid: _Optional[bytes] = ..., configurationUid: _Optional[bytes] = ..., controllerUid: _Optional[bytes] = ..., resourceUid: _Optional[bytes] = ..., noSchedule: bool = ...) -> None: ...

class RouterRecordRotationsRequest(_message.Message):
    __slots__ = ["enterpriseId", "records"]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    records: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, enterpriseId: _Optional[int] = ..., records: _Optional[_Iterable[bytes]] = ...) -> None: ...

class RouterRecordRotationsResponse(_message.Message):
    __slots__ = ["rotations", "hasMore"]
    ROTATIONS_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    rotations: _containers.RepeatedCompositeFieldContainer[RouterRecordRotation]
    hasMore: bool
    def __init__(self, rotations: _Optional[_Iterable[_Union[RouterRecordRotation, _Mapping]]] = ..., hasMore: bool = ...) -> None: ...

class RouterRotationInfo(_message.Message):
    __slots__ = ["status", "configurationUid", "resourceUid", "nodeId", "controllerUid", "controllerName", "scriptName", "pwdComplexity", "disabled"]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATIONUID_FIELD_NUMBER: _ClassVar[int]
    RESOURCEUID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERUID_FIELD_NUMBER: _ClassVar[int]
    CONTROLLERNAME_FIELD_NUMBER: _ClassVar[int]
    SCRIPTNAME_FIELD_NUMBER: _ClassVar[int]
    PWDCOMPLEXITY_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    status: RouterRotationStatus
    configurationUid: bytes
    resourceUid: bytes
    nodeId: int
    controllerUid: bytes
    controllerName: str
    scriptName: str
    pwdComplexity: str
    disabled: bool
    def __init__(self, status: _Optional[_Union[RouterRotationStatus, str]] = ..., configurationUid: _Optional[bytes] = ..., resourceUid: _Optional[bytes] = ..., nodeId: _Optional[int] = ..., controllerUid: _Optional[bytes] = ..., controllerName: _Optional[str] = ..., scriptName: _Optional[str] = ..., pwdComplexity: _Optional[str] = ..., disabled: bool = ...) -> None: ...

class RouterRecordRotationRequest(_message.Message):
    __slots__ = ["recordUid", "revision", "configurationUid", "resourceUid", "schedule", "enterpriseUserId", "pwdComplexity", "disabled"]
    RECORDUID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATIONUID_FIELD_NUMBER: _ClassVar[int]
    RESOURCEUID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    ENTERPRISEUSERID_FIELD_NUMBER: _ClassVar[int]
    PWDCOMPLEXITY_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    recordUid: bytes
    revision: int
    configurationUid: bytes
    resourceUid: bytes
    schedule: str
    enterpriseUserId: int
    pwdComplexity: bytes
    disabled: bool
    def __init__(self, recordUid: _Optional[bytes] = ..., revision: _Optional[int] = ..., configurationUid: _Optional[bytes] = ..., resourceUid: _Optional[bytes] = ..., schedule: _Optional[str] = ..., enterpriseUserId: _Optional[int] = ..., pwdComplexity: _Optional[bytes] = ..., disabled: bool = ...) -> None: ...
