from __future__ import annotations

import base64
import enum
from typing import Optional, List, Any, Dict

import attrs

from .. import utils


class RefType(str, enum.Enum):
    GENERAL = 'general'
    USER = 'user'
    DEVICE = 'device'
    REC = 'rec'
    FOLDER = 'folder'
    TEAM = 'team'
    ENTERPRISE = 'enterprise'
    PAM_DIRECTORY = 'pam_directory'
    PAM_MACHINE = 'pam_machine'
    PAM_DATABASE = 'pam_database'
    PAM_USER = 'pam_user'
    PAM_NETWORK = 'pam_network'

    @staticmethod
    def parse(value: Any) -> Optional[RefType]:
        if value is None:
            return None
        if isinstance(value, str):
            value = value.lower()
            r: RefType
            for r in list(RefType):
                if r.value == value:
                    return r
        raise ValueError(f'Invalid RefType value: {value}')


class EdgeType(str, enum.Enum):
    """
    DAG data type enum
    * DATA - encrypted data
    * KEY - encrypted key
    * LINK - like a key, but not encrypted
    * ACL - unencrypted set of access control flags
    * DELETION - removal of the previous edge at the same coordinates
    * DENIAL - an element that was shared through graph relationship, can be explicitly denied
    * UNDENIAL - negates the effect of denial, bringing back the share
    """

    DATA = 'data'
    KEY = 'key'
    LINK = 'link'
    ACL = 'acl'
    DELETION = 'deletion'
    DENIAL = 'denial'
    UNDENIAL = 'undenial'

    @staticmethod
    def parse(value: Any) -> Optional[EdgeType]:
        if value is None:
            return None
        if isinstance(value, str):
            value = value.lower()
            e: EdgeType
            for e in list(EdgeType):
                if e.value == value:
                    return e
        raise ValueError(f'Invalid EdgeType value: {value}')


class ActorType(str, enum.Enum):
    USER = 'user'
    SERVICE = 'service'
    PAM_GATEWAY = 'pam_gateway'

    @staticmethod
    def parse(value: Any) -> Optional[ActorType]:
        if value is None:
            return None
        if isinstance(value, str):
            value = value.lower()
            a: ActorType
            for a in list(ActorType):
                if a.value == value:
                    return a
        raise ValueError(f'Invalid ActorType value: {value}')

    
@attrs.define(frozen=True, kw_only=True)
class Ref:
    value: str
    type: RefType
    name: Optional[str] = None

    def dump(self) -> Dict[str, Any]:
        result = {
            'type': self.type.value,
            'value': self.value,
        }
        if self.name:
            result['name'] = self.name
        return result

    @staticmethod
    def parse(value: Any) -> Optional[Ref]:
        if value is None:
            return None
        if isinstance(value, dict):
            ref_type = RefType.parse(value.get('type')) or RefType.GENERAL
            ref_value: Optional[str] = value.get('value')
            if not ref_value:
                raise ValueError(f'Parse DAG "Ref": value is empty')
            return Ref(type=ref_type, value=ref_value, name=value.get('name'))

        raise ValueError(f'Parse DAG "Ref": value is invalid: {value}')


@attrs.define(frozen=True, kw_only=True)
class DagEdge:
    type: EdgeType
    ref: Ref
    content: Optional[bytes]
    parentRef: Optional[Ref] = None
    path: Optional[str] = None

    def __str__(self):
        return f'type: {self.type}; ref: {self.ref.value}; path: {(self.path or "")}'

    @staticmethod
    def parse(data: Any) -> Optional[DagEdge]:
        if data is None:
            return None
        if isinstance(data, dict):
            data_type = EdgeType.parse(data.get('type'))
            ref = Ref.parse(data.get('ref'))
            assert ref
            if 'parentRef' in data:
                parent_ref = Ref.parse(data.get('parentRef'))
            else:
                parent_ref = None
            if data_type is None:
                data_type = EdgeType.DATA if parent_ref is None else EdgeType.LINK
            c = data.get('content')
            content: Optional[bytes]
            if c is None:
                content = None
            elif isinstance(c, str):
                content = utils.base64_url_decode(c)
            else:
                raise ValueError(f'Parse DAG "content": value is invalid: {c}')
            path: Optional[str] = data.get('path')
            return DagEdge(type=data_type, ref=ref, parentRef=parent_ref, content=content, path=path)
        raise ValueError(f'Parse DAG "DagEdge": value is invalid: {data}')

    def dump(self) -> Dict[str, Any]:
        result = {
            'type': self.type.value,
            'ref': self.ref.dump(),
        }
        if self.parentRef:
            result['parentRef'] = self.parentRef.dump()
        if self.content:
            result['content'] = base64.b64encode(self.content).decode('ascii')
        if self.path:
            result['path'] = self.path
        return result


@attrs.define(frozen=True, kw_only=True)
class DagActor:
    type: ActorType
    actor_id: str
    name: Optional[str] = None
    user_id: Optional[str] = None

    @staticmethod
    def parse(data: Any) -> Optional[DagActor]:
        if data is None:
            return None
        if isinstance(data, dict):
            a_type = ActorType.parse(data.get('type'))
            if a_type is None:
                raise ValueError(f'Parse DAG "DagActor": "type" is empty')

            actor_id: Optional[str] = data.get('id')
            if not actor_id:
                raise ValueError(f'Parse DAG "DagActor": "id" is empty')
            if not isinstance(actor_id, str):
                raise ValueError(f'Parse DAG "DagActor": "id" is invalid: {actor_id}')

            user_id_value: Optional[str] = None
            s = data.get('effectiveUserId')
            if s:
                if not isinstance(s, str):
                    raise ValueError(f'Parse DAG "DagActor": Invalid "effectiveUserId" valie: {s}')
            return DagActor(type=a_type, actor_id=actor_id, user_id=user_id_value, name=data.get('name'))
        raise ValueError(f'Parse DAG "DagActor": "id" is invalid: {data}')

    def dump(self) -> Dict[str, Any]:
        result = {
            'type': self.type.value,
            'id': self.actor_id,
        }
        if self.name:
            result['name'] = self.name
        if self.user_id:
            result['effectiveUserId'] = self.user_id
        return result


@attrs.define(frozen=True, kw_only=True)
class DagAddRequest:
    graph_id: int
    origin: Ref
    data_list: List[DagEdge]
    actor: Optional[DagActor] = None

    def to_dict(self) -> Dict[str, Any]:
        data_list: List[Dict[str, Any]] = [x.dump() for x in self.data_list]
        result = {
            'graphId': self.graph_id,
            'origin': self.origin.dump(),
            'dataList': data_list,
        }
        if self.actor:
            result['actor'] = self.actor.dump()
        return result


@attrs.define(kw_only=True)
class DagSyncRequest:
    graph_id: int
    stream_id: str
    sync_point: int = 0
    device_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'graphId': self.graph_id,
            'streamId': self.stream_id,
            'syncPoint': self.sync_point,
            'deviceId': self.device_id
        }

