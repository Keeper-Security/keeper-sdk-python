from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RefType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RFT_UNSPECIFIED: _ClassVar[RefType]
    RFT_GENERAL: _ClassVar[RefType]
    USER: _ClassVar[RefType]
    DEVICE: _ClassVar[RefType]
    REC: _ClassVar[RefType]
    FOLDER: _ClassVar[RefType]
    TEAM: _ClassVar[RefType]
    ENTERPRISE: _ClassVar[RefType]
    PAM_DIRECTORY: _ClassVar[RefType]
    PAM_MACHINE: _ClassVar[RefType]
    PAM_DATABASE: _ClassVar[RefType]
    PAM_USER: _ClassVar[RefType]
    PAM_NETWORK: _ClassVar[RefType]
    PAM_BROWSER: _ClassVar[RefType]
    CONNECTION: _ClassVar[RefType]
    WORKFLOW: _ClassVar[RefType]
    NOTIFICATION: _ClassVar[RefType]
    USER_INFO: _ClassVar[RefType]
    TEAM_INFO: _ClassVar[RefType]
    ROLE: _ClassVar[RefType]

class GraphSyncDataType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GSE_UNSPECIFIED: _ClassVar[GraphSyncDataType]
    GSE_DATA: _ClassVar[GraphSyncDataType]
    GSE_KEY: _ClassVar[GraphSyncDataType]
    GSE_LINK: _ClassVar[GraphSyncDataType]
    GSE_ACL: _ClassVar[GraphSyncDataType]
    GSE_DELETION: _ClassVar[GraphSyncDataType]

class GraphSyncActorType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    GSA_UNSPECIFIED: _ClassVar[GraphSyncActorType]
    GSA_USER: _ClassVar[GraphSyncActorType]
    GSA_SERVICE: _ClassVar[GraphSyncActorType]
    GSA_PAM_GATEWAY: _ClassVar[GraphSyncActorType]
RFT_UNSPECIFIED: RefType
RFT_GENERAL: RefType
USER: RefType
DEVICE: RefType
REC: RefType
FOLDER: RefType
TEAM: RefType
ENTERPRISE: RefType
PAM_DIRECTORY: RefType
PAM_MACHINE: RefType
PAM_DATABASE: RefType
PAM_USER: RefType
PAM_NETWORK: RefType
PAM_BROWSER: RefType
CONNECTION: RefType
WORKFLOW: RefType
NOTIFICATION: RefType
USER_INFO: RefType
TEAM_INFO: RefType
ROLE: RefType
GSE_UNSPECIFIED: GraphSyncDataType
GSE_DATA: GraphSyncDataType
GSE_KEY: GraphSyncDataType
GSE_LINK: GraphSyncDataType
GSE_ACL: GraphSyncDataType
GSE_DELETION: GraphSyncDataType
GSA_UNSPECIFIED: GraphSyncActorType
GSA_USER: GraphSyncActorType
GSA_SERVICE: GraphSyncActorType
GSA_PAM_GATEWAY: GraphSyncActorType

class GraphSyncRef(_message.Message):
    __slots__ = ("type", "value", "name")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    type: RefType
    value: bytes
    name: str
    def __init__(self, type: _Optional[_Union[RefType, str]] = ..., value: _Optional[bytes] = ..., name: _Optional[str] = ...) -> None: ...

class GraphSyncActor(_message.Message):
    __slots__ = ("type", "id", "name", "effectiveUserId")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    EFFECTIVEUSERID_FIELD_NUMBER: _ClassVar[int]
    type: GraphSyncActorType
    id: bytes
    name: str
    effectiveUserId: bytes
    def __init__(self, type: _Optional[_Union[GraphSyncActorType, str]] = ..., id: _Optional[bytes] = ..., name: _Optional[str] = ..., effectiveUserId: _Optional[bytes] = ...) -> None: ...

class GraphSyncData(_message.Message):
    __slots__ = ("type", "ref", "parentRef", "content", "path")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    REF_FIELD_NUMBER: _ClassVar[int]
    PARENTREF_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    type: GraphSyncDataType
    ref: GraphSyncRef
    parentRef: GraphSyncRef
    content: bytes
    path: str
    def __init__(self, type: _Optional[_Union[GraphSyncDataType, str]] = ..., ref: _Optional[_Union[GraphSyncRef, _Mapping]] = ..., parentRef: _Optional[_Union[GraphSyncRef, _Mapping]] = ..., content: _Optional[bytes] = ..., path: _Optional[str] = ...) -> None: ...

class GraphSyncDataPlus(_message.Message):
    __slots__ = ("data", "timestamp", "actor")
    DATA_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    ACTOR_FIELD_NUMBER: _ClassVar[int]
    data: GraphSyncData
    timestamp: int
    actor: GraphSyncActor
    def __init__(self, data: _Optional[_Union[GraphSyncData, _Mapping]] = ..., timestamp: _Optional[int] = ..., actor: _Optional[_Union[GraphSyncActor, _Mapping]] = ...) -> None: ...

class GraphSyncQuery(_message.Message):
    __slots__ = ("streamId", "origin", "syncPoint", "maxCount")
    STREAMID_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    SYNCPOINT_FIELD_NUMBER: _ClassVar[int]
    MAXCOUNT_FIELD_NUMBER: _ClassVar[int]
    streamId: bytes
    origin: bytes
    syncPoint: int
    maxCount: int
    def __init__(self, streamId: _Optional[bytes] = ..., origin: _Optional[bytes] = ..., syncPoint: _Optional[int] = ..., maxCount: _Optional[int] = ...) -> None: ...

class GraphSyncResult(_message.Message):
    __slots__ = ("streamId", "syncPoint", "data", "hasMore")
    STREAMID_FIELD_NUMBER: _ClassVar[int]
    SYNCPOINT_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    HASMORE_FIELD_NUMBER: _ClassVar[int]
    streamId: bytes
    syncPoint: int
    data: _containers.RepeatedCompositeFieldContainer[GraphSyncDataPlus]
    hasMore: bool
    def __init__(self, streamId: _Optional[bytes] = ..., syncPoint: _Optional[int] = ..., data: _Optional[_Iterable[_Union[GraphSyncDataPlus, _Mapping]]] = ..., hasMore: bool = ...) -> None: ...

class GraphSyncMultiQuery(_message.Message):
    __slots__ = ("queries",)
    QUERIES_FIELD_NUMBER: _ClassVar[int]
    queries: _containers.RepeatedCompositeFieldContainer[GraphSyncQuery]
    def __init__(self, queries: _Optional[_Iterable[_Union[GraphSyncQuery, _Mapping]]] = ...) -> None: ...

class GraphSyncMultiResult(_message.Message):
    __slots__ = ("results",)
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    results: _containers.RepeatedCompositeFieldContainer[GraphSyncResult]
    def __init__(self, results: _Optional[_Iterable[_Union[GraphSyncResult, _Mapping]]] = ...) -> None: ...

class GraphSyncAddDataRequest(_message.Message):
    __slots__ = ("origin", "data")
    ORIGIN_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    origin: GraphSyncRef
    data: _containers.RepeatedCompositeFieldContainer[GraphSyncData]
    def __init__(self, origin: _Optional[_Union[GraphSyncRef, _Mapping]] = ..., data: _Optional[_Iterable[_Union[GraphSyncData, _Mapping]]] = ...) -> None: ...

class GraphSyncLeafsQuery(_message.Message):
    __slots__ = ("vertices",)
    VERTICES_FIELD_NUMBER: _ClassVar[int]
    vertices: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, vertices: _Optional[_Iterable[bytes]] = ...) -> None: ...

class GraphSyncRefsResult(_message.Message):
    __slots__ = ("refs",)
    REFS_FIELD_NUMBER: _ClassVar[int]
    refs: _containers.RepeatedCompositeFieldContainer[GraphSyncRef]
    def __init__(self, refs: _Optional[_Iterable[_Union[GraphSyncRef, _Mapping]]] = ...) -> None: ...
