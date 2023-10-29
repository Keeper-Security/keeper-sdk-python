import ssocloud_pb2 as _ssocloud_pb2
import enterprise_pb2 as _enterprise_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SsoAuthenticationProtocolType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    UNKNOWN_PROTOCOL: _ClassVar[SsoAuthenticationProtocolType]
    SAML2: _ClassVar[SsoAuthenticationProtocolType]

class CertificateFormat(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    UNKNOWN_FORMAT: _ClassVar[CertificateFormat]
    PKCS12: _ClassVar[CertificateFormat]
    JKS: _ClassVar[CertificateFormat]

class SkillType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    UNKNOWN_SKILL_TYPE: _ClassVar[SkillType]
    DEVICE_APPROVAL: _ClassVar[SkillType]
    TEAM_APPROVAL: _ClassVar[SkillType]

class AutomatorState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
    UNKNOWN_STATE: _ClassVar[AutomatorState]
    RUNNING: _ClassVar[AutomatorState]
    ERROR: _ClassVar[AutomatorState]
    NEEDS_INITIALIZATION: _ClassVar[AutomatorState]
    NEEDS_CRYPTO_STEP_1: _ClassVar[AutomatorState]
    NEEDS_CRYPTO_STEP_2: _ClassVar[AutomatorState]
UNKNOWN_PROTOCOL: SsoAuthenticationProtocolType
SAML2: SsoAuthenticationProtocolType
UNKNOWN_FORMAT: CertificateFormat
PKCS12: CertificateFormat
JKS: CertificateFormat
UNKNOWN_SKILL_TYPE: SkillType
DEVICE_APPROVAL: SkillType
TEAM_APPROVAL: SkillType
UNKNOWN_STATE: AutomatorState
RUNNING: AutomatorState
ERROR: AutomatorState
NEEDS_INITIALIZATION: AutomatorState
NEEDS_CRYPTO_STEP_1: AutomatorState
NEEDS_CRYPTO_STEP_2: AutomatorState

class AutomatorSettingValue(_message.Message):
    __slots__ = ["settingId", "settingTypeId", "settingTag", "settingName", "settingValue", "dataType", "lastModified", "fromFile", "encrypted", "encoded", "editable", "translated", "userVisible", "required"]
    SETTINGID_FIELD_NUMBER: _ClassVar[int]
    SETTINGTYPEID_FIELD_NUMBER: _ClassVar[int]
    SETTINGTAG_FIELD_NUMBER: _ClassVar[int]
    SETTINGNAME_FIELD_NUMBER: _ClassVar[int]
    SETTINGVALUE_FIELD_NUMBER: _ClassVar[int]
    DATATYPE_FIELD_NUMBER: _ClassVar[int]
    LASTMODIFIED_FIELD_NUMBER: _ClassVar[int]
    FROMFILE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_FIELD_NUMBER: _ClassVar[int]
    ENCODED_FIELD_NUMBER: _ClassVar[int]
    EDITABLE_FIELD_NUMBER: _ClassVar[int]
    TRANSLATED_FIELD_NUMBER: _ClassVar[int]
    USERVISIBLE_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    settingId: int
    settingTypeId: int
    settingTag: str
    settingName: str
    settingValue: str
    dataType: _ssocloud_pb2.DataType
    lastModified: str
    fromFile: bool
    encrypted: bool
    encoded: bool
    editable: bool
    translated: bool
    userVisible: bool
    required: bool
    def __init__(self, settingId: _Optional[int] = ..., settingTypeId: _Optional[int] = ..., settingTag: _Optional[str] = ..., settingName: _Optional[str] = ..., settingValue: _Optional[str] = ..., dataType: _Optional[_Union[_ssocloud_pb2.DataType, str]] = ..., lastModified: _Optional[str] = ..., fromFile: bool = ..., encrypted: bool = ..., encoded: bool = ..., editable: bool = ..., translated: bool = ..., userVisible: bool = ..., required: bool = ...) -> None: ...

class ApproveDeviceRequest(_message.Message):
    __slots__ = ["automatorId", "ssoAuthenticationProtocolType", "authMessage", "email", "devicePublicKey", "serverEccPublicKeyId", "userEncryptedDataKey", "userEncryptedDataKeyType", "ipAddress"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    SSOAUTHENTICATIONPROTOCOLTYPE_FIELD_NUMBER: _ClassVar[int]
    AUTHMESSAGE_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    DEVICEPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    SERVERECCPUBLICKEYID_FIELD_NUMBER: _ClassVar[int]
    USERENCRYPTEDDATAKEY_FIELD_NUMBER: _ClassVar[int]
    USERENCRYPTEDDATAKEYTYPE_FIELD_NUMBER: _ClassVar[int]
    IPADDRESS_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    ssoAuthenticationProtocolType: SsoAuthenticationProtocolType
    authMessage: str
    email: str
    devicePublicKey: bytes
    serverEccPublicKeyId: int
    userEncryptedDataKey: bytes
    userEncryptedDataKeyType: _enterprise_pb2.EncryptedKeyType
    ipAddress: str
    def __init__(self, automatorId: _Optional[int] = ..., ssoAuthenticationProtocolType: _Optional[_Union[SsoAuthenticationProtocolType, str]] = ..., authMessage: _Optional[str] = ..., email: _Optional[str] = ..., devicePublicKey: _Optional[bytes] = ..., serverEccPublicKeyId: _Optional[int] = ..., userEncryptedDataKey: _Optional[bytes] = ..., userEncryptedDataKeyType: _Optional[_Union[_enterprise_pb2.EncryptedKeyType, str]] = ..., ipAddress: _Optional[str] = ...) -> None: ...

class SetupRequest(_message.Message):
    __slots__ = ["automatorId", "serverEccPublicKeyId", "automatorState", "encryptedEnterprisePrivateEcKey", "encryptedEnterprisePrivateRsaKey"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    SERVERECCPUBLICKEYID_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSTATE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDENTERPRISEPRIVATEECKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDENTERPRISEPRIVATERSAKEY_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    serverEccPublicKeyId: int
    automatorState: AutomatorState
    encryptedEnterprisePrivateEcKey: bytes
    encryptedEnterprisePrivateRsaKey: bytes
    def __init__(self, automatorId: _Optional[int] = ..., serverEccPublicKeyId: _Optional[int] = ..., automatorState: _Optional[_Union[AutomatorState, str]] = ..., encryptedEnterprisePrivateEcKey: _Optional[bytes] = ..., encryptedEnterprisePrivateRsaKey: _Optional[bytes] = ...) -> None: ...

class StatusRequest(_message.Message):
    __slots__ = ["automatorId", "serverEccPublicKeyId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    SERVERECCPUBLICKEYID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    serverEccPublicKeyId: int
    def __init__(self, automatorId: _Optional[int] = ..., serverEccPublicKeyId: _Optional[int] = ...) -> None: ...

class InitializeRequest(_message.Message):
    __slots__ = ["automatorId", "idpMetadata", "idpSigningCertificate", "ssoEntityId", "emailMapping", "firstnameMapping", "lastnameMapping", "disabled", "serverEccPublicKeyId", "config", "sslMode", "persistState", "disableSniCheck", "sslCertificateFilename", "sslCertificateFilePassword", "sslCertificateKeyPassword", "sslCertificateContents", "automatorHost", "automatorPort", "ipAllow", "ipDeny"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    IDPMETADATA_FIELD_NUMBER: _ClassVar[int]
    IDPSIGNINGCERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    SSOENTITYID_FIELD_NUMBER: _ClassVar[int]
    EMAILMAPPING_FIELD_NUMBER: _ClassVar[int]
    FIRSTNAMEMAPPING_FIELD_NUMBER: _ClassVar[int]
    LASTNAMEMAPPING_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    SERVERECCPUBLICKEYID_FIELD_NUMBER: _ClassVar[int]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    SSLMODE_FIELD_NUMBER: _ClassVar[int]
    PERSISTSTATE_FIELD_NUMBER: _ClassVar[int]
    DISABLESNICHECK_FIELD_NUMBER: _ClassVar[int]
    SSLCERTIFICATEFILENAME_FIELD_NUMBER: _ClassVar[int]
    SSLCERTIFICATEFILEPASSWORD_FIELD_NUMBER: _ClassVar[int]
    SSLCERTIFICATEKEYPASSWORD_FIELD_NUMBER: _ClassVar[int]
    SSLCERTIFICATECONTENTS_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORHOST_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORPORT_FIELD_NUMBER: _ClassVar[int]
    IPALLOW_FIELD_NUMBER: _ClassVar[int]
    IPDENY_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    idpMetadata: str
    idpSigningCertificate: bytes
    ssoEntityId: str
    emailMapping: str
    firstnameMapping: str
    lastnameMapping: str
    disabled: bool
    serverEccPublicKeyId: int
    config: bytes
    sslMode: str
    persistState: bool
    disableSniCheck: bool
    sslCertificateFilename: str
    sslCertificateFilePassword: str
    sslCertificateKeyPassword: str
    sslCertificateContents: bytes
    automatorHost: str
    automatorPort: str
    ipAllow: str
    ipDeny: str
    def __init__(self, automatorId: _Optional[int] = ..., idpMetadata: _Optional[str] = ..., idpSigningCertificate: _Optional[bytes] = ..., ssoEntityId: _Optional[str] = ..., emailMapping: _Optional[str] = ..., firstnameMapping: _Optional[str] = ..., lastnameMapping: _Optional[str] = ..., disabled: bool = ..., serverEccPublicKeyId: _Optional[int] = ..., config: _Optional[bytes] = ..., sslMode: _Optional[str] = ..., persistState: bool = ..., disableSniCheck: bool = ..., sslCertificateFilename: _Optional[str] = ..., sslCertificateFilePassword: _Optional[str] = ..., sslCertificateKeyPassword: _Optional[str] = ..., sslCertificateContents: _Optional[bytes] = ..., automatorHost: _Optional[str] = ..., automatorPort: _Optional[str] = ..., ipAllow: _Optional[str] = ..., ipDeny: _Optional[str] = ...) -> None: ...

class NotInitializedResponse(_message.Message):
    __slots__ = ["automatorTransmissionKey", "signingCertificate", "signingCertificateFilename", "signingCertificatePassword", "signingKeyPassword", "signingCertificateFormat", "automatorPublicKey", "config"]
    AUTOMATORTRANSMISSIONKEY_FIELD_NUMBER: _ClassVar[int]
    SIGNINGCERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    SIGNINGCERTIFICATEFILENAME_FIELD_NUMBER: _ClassVar[int]
    SIGNINGCERTIFICATEPASSWORD_FIELD_NUMBER: _ClassVar[int]
    SIGNINGKEYPASSWORD_FIELD_NUMBER: _ClassVar[int]
    SIGNINGCERTIFICATEFORMAT_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    automatorTransmissionKey: bytes
    signingCertificate: bytes
    signingCertificateFilename: str
    signingCertificatePassword: str
    signingKeyPassword: str
    signingCertificateFormat: CertificateFormat
    automatorPublicKey: bytes
    config: bytes
    def __init__(self, automatorTransmissionKey: _Optional[bytes] = ..., signingCertificate: _Optional[bytes] = ..., signingCertificateFilename: _Optional[str] = ..., signingCertificatePassword: _Optional[str] = ..., signingKeyPassword: _Optional[str] = ..., signingCertificateFormat: _Optional[_Union[CertificateFormat, str]] = ..., automatorPublicKey: _Optional[bytes] = ..., config: _Optional[bytes] = ...) -> None: ...

class AutomatorResponse(_message.Message):
    __slots__ = ["automatorId", "enabled", "timestamp", "approveDevice", "status", "notInitialized", "error", "automatorState", "automatorPublicEcKey"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    APPROVEDEVICE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    NOTINITIALIZED_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSTATE_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORPUBLICECKEY_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    enabled: bool
    timestamp: int
    approveDevice: ApproveDeviceResponse
    status: StatusResponse
    notInitialized: NotInitializedResponse
    error: ErrorResponse
    automatorState: AutomatorState
    automatorPublicEcKey: bytes
    def __init__(self, automatorId: _Optional[int] = ..., enabled: bool = ..., timestamp: _Optional[int] = ..., approveDevice: _Optional[_Union[ApproveDeviceResponse, _Mapping]] = ..., status: _Optional[_Union[StatusResponse, _Mapping]] = ..., notInitialized: _Optional[_Union[NotInitializedResponse, _Mapping]] = ..., error: _Optional[_Union[ErrorResponse, _Mapping]] = ..., automatorState: _Optional[_Union[AutomatorState, str]] = ..., automatorPublicEcKey: _Optional[bytes] = ...) -> None: ...

class ApproveDeviceResponse(_message.Message):
    __slots__ = ["approved", "encryptedUserDataKey", "message"]
    APPROVED_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDUSERDATAKEY_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    approved: bool
    encryptedUserDataKey: bytes
    message: str
    def __init__(self, approved: bool = ..., encryptedUserDataKey: _Optional[bytes] = ..., message: _Optional[str] = ...) -> None: ...

class StatusResponse(_message.Message):
    __slots__ = ["initialized", "enabledTimestamp", "initializedTimestamp", "updatedTimestamp", "numberOfDevicesApproved", "numberOfDevicesDenied", "numberOfErrors", "sslCertificateExpiration", "notInitializedResponse", "config"]
    INITIALIZED_FIELD_NUMBER: _ClassVar[int]
    ENABLEDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    INITIALIZEDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    UPDATEDTIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFDEVICESAPPROVED_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFDEVICESDENIED_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFERRORS_FIELD_NUMBER: _ClassVar[int]
    SSLCERTIFICATEEXPIRATION_FIELD_NUMBER: _ClassVar[int]
    NOTINITIALIZEDRESPONSE_FIELD_NUMBER: _ClassVar[int]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    initialized: bool
    enabledTimestamp: int
    initializedTimestamp: int
    updatedTimestamp: int
    numberOfDevicesApproved: int
    numberOfDevicesDenied: int
    numberOfErrors: int
    sslCertificateExpiration: int
    notInitializedResponse: NotInitializedResponse
    config: bytes
    def __init__(self, initialized: bool = ..., enabledTimestamp: _Optional[int] = ..., initializedTimestamp: _Optional[int] = ..., updatedTimestamp: _Optional[int] = ..., numberOfDevicesApproved: _Optional[int] = ..., numberOfDevicesDenied: _Optional[int] = ..., numberOfErrors: _Optional[int] = ..., sslCertificateExpiration: _Optional[int] = ..., notInitializedResponse: _Optional[_Union[NotInitializedResponse, _Mapping]] = ..., config: _Optional[bytes] = ...) -> None: ...

class ErrorResponse(_message.Message):
    __slots__ = ["message"]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class LogEntry(_message.Message):
    __slots__ = ["serverTime", "messageLevel", "component", "message"]
    SERVERTIME_FIELD_NUMBER: _ClassVar[int]
    MESSAGELEVEL_FIELD_NUMBER: _ClassVar[int]
    COMPONENT_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    serverTime: str
    messageLevel: str
    component: str
    message: str
    def __init__(self, serverTime: _Optional[str] = ..., messageLevel: _Optional[str] = ..., component: _Optional[str] = ..., message: _Optional[str] = ...) -> None: ...

class AdminResponse(_message.Message):
    __slots__ = ["success", "message", "automatorInfo"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORINFO_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    automatorInfo: _containers.RepeatedCompositeFieldContainer[AutomatorInfo]
    def __init__(self, success: bool = ..., message: _Optional[str] = ..., automatorInfo: _Optional[_Iterable[_Union[AutomatorInfo, _Mapping]]] = ...) -> None: ...

class AutomatorInfo(_message.Message):
    __slots__ = ["automatorId", "nodeId", "name", "enabled", "url", "automatorSkills", "automatorSettingValues", "status", "logEntries", "automatorState"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSKILLS_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSETTINGVALUES_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    LOGENTRIES_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSTATE_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    nodeId: int
    name: str
    enabled: bool
    url: str
    automatorSkills: _containers.RepeatedCompositeFieldContainer[AutomatorSkill]
    automatorSettingValues: _containers.RepeatedCompositeFieldContainer[AutomatorSettingValue]
    status: StatusResponse
    logEntries: _containers.RepeatedCompositeFieldContainer[LogEntry]
    automatorState: AutomatorState
    def __init__(self, automatorId: _Optional[int] = ..., nodeId: _Optional[int] = ..., name: _Optional[str] = ..., enabled: bool = ..., url: _Optional[str] = ..., automatorSkills: _Optional[_Iterable[_Union[AutomatorSkill, _Mapping]]] = ..., automatorSettingValues: _Optional[_Iterable[_Union[AutomatorSettingValue, _Mapping]]] = ..., status: _Optional[_Union[StatusResponse, _Mapping]] = ..., logEntries: _Optional[_Iterable[_Union[LogEntry, _Mapping]]] = ..., automatorState: _Optional[_Union[AutomatorState, str]] = ...) -> None: ...

class AdminCreateAutomatorRequest(_message.Message):
    __slots__ = ["nodeId", "name", "skill"]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SKILL_FIELD_NUMBER: _ClassVar[int]
    nodeId: int
    name: str
    skill: AutomatorSkill
    def __init__(self, nodeId: _Optional[int] = ..., name: _Optional[str] = ..., skill: _Optional[_Union[AutomatorSkill, _Mapping]] = ...) -> None: ...

class AdminDeleteAutomatorRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...

class AdminGetAutomatorsOnNodeRequest(_message.Message):
    __slots__ = ["nodeId"]
    NODEID_FIELD_NUMBER: _ClassVar[int]
    nodeId: int
    def __init__(self, nodeId: _Optional[int] = ...) -> None: ...

class AdminGetAutomatorsForEnterpriseRequest(_message.Message):
    __slots__ = ["enterpriseId"]
    ENTERPRISEID_FIELD_NUMBER: _ClassVar[int]
    enterpriseId: int
    def __init__(self, enterpriseId: _Optional[int] = ...) -> None: ...

class AdminGetAutomatorRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...

class AdminEnableAutomatorRequest(_message.Message):
    __slots__ = ["automatorId", "enabled"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    enabled: bool
    def __init__(self, automatorId: _Optional[int] = ..., enabled: bool = ...) -> None: ...

class AdminEditAutomatorRequest(_message.Message):
    __slots__ = ["automatorId", "name", "enabled", "url", "skillTypes", "automatorSettingValues"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    SKILLTYPES_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSETTINGVALUES_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    name: str
    enabled: bool
    url: str
    skillTypes: _containers.RepeatedScalarFieldContainer[SkillType]
    automatorSettingValues: _containers.RepeatedCompositeFieldContainer[AutomatorSettingValue]
    def __init__(self, automatorId: _Optional[int] = ..., name: _Optional[str] = ..., enabled: bool = ..., url: _Optional[str] = ..., skillTypes: _Optional[_Iterable[_Union[SkillType, str]]] = ..., automatorSettingValues: _Optional[_Iterable[_Union[AutomatorSettingValue, _Mapping]]] = ...) -> None: ...

class AdminSetupAutomatorRequest(_message.Message):
    __slots__ = ["automatorId", "automatorState", "encryptedEcEnterprisePrivateKey", "encryptedRsaEnterprisePrivateKey"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSTATE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDECENTERPRISEPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTEDRSAENTERPRISEPRIVATEKEY_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    automatorState: AutomatorState
    encryptedEcEnterprisePrivateKey: bytes
    encryptedRsaEnterprisePrivateKey: bytes
    def __init__(self, automatorId: _Optional[int] = ..., automatorState: _Optional[_Union[AutomatorState, str]] = ..., encryptedEcEnterprisePrivateKey: _Optional[bytes] = ..., encryptedRsaEnterprisePrivateKey: _Optional[bytes] = ...) -> None: ...

class AdminSetupAutomatorResponse(_message.Message):
    __slots__ = ["success", "message", "automatorId", "automatorState", "automatorEcPublicKey"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSTATE_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORECPUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    automatorId: int
    automatorState: AutomatorState
    automatorEcPublicKey: bytes
    def __init__(self, success: bool = ..., message: _Optional[str] = ..., automatorId: _Optional[int] = ..., automatorState: _Optional[_Union[AutomatorState, str]] = ..., automatorEcPublicKey: _Optional[bytes] = ...) -> None: ...

class AdminAutomatorSkillsRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...

class AutomatorSkill(_message.Message):
    __slots__ = ["skillType", "name", "translatedName"]
    SKILLTYPE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TRANSLATEDNAME_FIELD_NUMBER: _ClassVar[int]
    skillType: SkillType
    name: str
    translatedName: str
    def __init__(self, skillType: _Optional[_Union[SkillType, str]] = ..., name: _Optional[str] = ..., translatedName: _Optional[str] = ...) -> None: ...

class AdminAutomatorSkillsResponse(_message.Message):
    __slots__ = ["success", "message", "automatorSkills"]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    AUTOMATORSKILLS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    automatorSkills: _containers.RepeatedCompositeFieldContainer[AutomatorSkill]
    def __init__(self, success: bool = ..., message: _Optional[str] = ..., automatorSkills: _Optional[_Iterable[_Union[AutomatorSkill, _Mapping]]] = ...) -> None: ...

class AdminResetAutomatorRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...

class AdminInitializeAutomatorRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...

class AdminAutomatorLogRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...

class AdminAutomatorLogClearRequest(_message.Message):
    __slots__ = ["automatorId"]
    AUTOMATORID_FIELD_NUMBER: _ClassVar[int]
    automatorId: int
    def __init__(self, automatorId: _Optional[int] = ...) -> None: ...
