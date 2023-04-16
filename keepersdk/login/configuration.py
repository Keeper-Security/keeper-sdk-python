#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import abc
import io
import json
import os
from typing import Type, Union, TypeVar, Optional, Generic, Iterator
from urllib.parse import urlparse

from .. import utils
from ..constants import DEFAULT_KEEPER_SERVER


def adjust_username(username):   # type: (str) -> str
    return username.lower() if isinstance(username, str) else ''


def adjust_servername(server):   # type: (str) -> str
    if server:
        url = urlparse(server)
        if url.netloc:
            return url.netloc.lower()
        if url.path:
            return url.path.lower()
    return DEFAULT_KEEPER_SERVER


class IEntityId(abc.ABC):
    def __init__(self):
        super(IEntityId, self).__init__()

    @abc.abstractmethod
    def get_id(self):   # type: () -> str
        pass


TID = TypeVar('TID', bound=IEntityId)


class IConfigurationCollection(Generic[TID], abc.ABC):
    @abc.abstractmethod
    def get(self, entity_id):   # type: (str) -> Optional[TID]
        pass

    @abc.abstractmethod
    def put(self, entity):    # type: (TID) -> None
        pass

    @abc.abstractmethod
    def delete(self, entity_id):   # type: (str) -> None
        pass

    @abc.abstractmethod
    def list(self):   # type: () -> Iterator[TID]
        pass


class IUserDeviceConfiguration(IEntityId):
    def __init__(self):
        super(IUserDeviceConfiguration, self).__init__()

    @property
    @abc.abstractmethod
    def device_token(self):  # type: () -> str
        pass

    def get_id(self):
        return self.device_token


class IUserConfiguration(IEntityId):
    def __init__(self):
        super(IUserConfiguration, self).__init__()
        
    @property
    @abc.abstractmethod
    def username(self):   # type: () -> str
        pass

    @property
    @abc.abstractmethod
    def password(self):   # type: () -> Optional[str]
        pass

    @property
    @abc.abstractmethod
    def server(self):   # type: () -> Optional[str]
        pass

    @property
    @abc.abstractmethod
    def last_device(self):   # type: () -> Optional[IUserDeviceConfiguration]
        pass

    def get_id(self):
        return self.username


class IServerConfiguration(IEntityId):
    def __init__(self):
        super(IServerConfiguration, self).__init__()

    @property
    @abc.abstractmethod
    def server(self):  # type: () -> str
        pass

    @property
    @abc.abstractmethod
    def server_key_id(self):  # type: () -> int
        pass

    def get_id(self):
        return self.server


class IDeviceServerConfiguration(IEntityId):
    def __init__(self):
        super(IDeviceServerConfiguration, self).__init__()

    @property
    @abc.abstractmethod
    def server(self):   # type: () -> str
        pass

    @property
    @abc.abstractmethod
    def clone_code(self):   # type: () -> Optional[str]
        pass

    def get_id(self):
        return self.server


class IDeviceConfiguration(IEntityId):
    def __init__(self):
        super(IDeviceConfiguration, self).__init__()

    @property
    @abc.abstractmethod
    def device_token(self):   # type: () -> str
        pass

    @property
    @abc.abstractmethod
    def public_key(self):  # type: () -> str
        pass

    @property
    @abc.abstractmethod
    def private_key(self):  # type: () -> str
        pass

    @abc.abstractmethod
    def get_server_info(self):   # type: () -> IConfigurationCollection[IDeviceServerConfiguration]
        pass

    def get_id(self):
        return self.device_token


class IKeeperConfiguration(abc.ABC):
    def __init__(self):
        super(IKeeperConfiguration, self).__init__()

    @abc.abstractmethod
    def users(self):     # type: () -> IConfigurationCollection[IUserConfiguration]
        pass

    @abc.abstractmethod
    def servers(self):   # type: () -> IConfigurationCollection[IServerConfiguration]
        pass

    @abc.abstractmethod
    def devices(self):   # type: () -> IConfigurationCollection[IDeviceConfiguration]
        pass

    @property
    @abc.abstractmethod
    def last_login(self):   # type: () -> str
        pass

    @last_login.setter
    @abc.abstractmethod
    def last_login(self, value):   # type: (str) -> None
        pass

    @property
    @abc.abstractmethod
    def last_server(self):   # type: () -> str
        pass

    @last_server.setter
    @abc.abstractmethod
    def last_server(self, value):    # type: (str) -> None
        pass

    def assign(self, other):   # type: (IKeeperConfiguration) -> None
        user_ids = [x.get_id() for x in self.users().list()]
        for user_id in user_ids:
            self.users().delete(user_id)
        server_ids = [x.get_id() for x in self.servers().list()]
        for server_id in server_ids:
            self.servers().delete(server_id)
        device_ids = [x.get_id() for x in self.devices().list()]
        for device_id in device_ids:
            self.devices().delete(device_id)

        self.last_login = other.last_login
        self.last_server = other.last_server
        for user in other.users().list():
            self.users().put(user)
        for server in other.servers().list():
            self.servers().put(server)
        for device in other.devices().list():
            self.devices().put(device)


class IConfigurationStorage(abc.ABC):
    @abc.abstractmethod
    def get(self):  # type: () -> IKeeperConfiguration
        pass

    @abc.abstractmethod
    def put(self, configuration):  # type: (IKeeperConfiguration) -> None
        pass


class ConfigurationCollection(IConfigurationCollection):
    def __init__(self):
        super(ConfigurationCollection, self).__init__()
        self._storage = {} 

    def get(self, entity_id):
        return self._storage.get(entity_id)

    def put(self, entity):
        self._storage[entity.get_id()] = entity

    def delete(self, entity_id):
        if entity_id in self._storage:
            del self._storage[entity_id]

    def list(self):
        return self._storage.values()


class UserDeviceConfiguration(IUserDeviceConfiguration):
    def __init__(self, user_device):   # type: (Union[str, IUserDeviceConfiguration]) -> None
        IUserDeviceConfiguration.__init__(self)

        self._device_token = ''
        if isinstance(user_device, str):
            self._device_token = user_device
        elif isinstance(user_device, IUserDeviceConfiguration):
            self._device_token = user_device.device_token

    @property
    def device_token(self):
        return self._device_token


class UserConfiguration(IUserConfiguration):
    def __init__(self, user):   # type: (Union[IUserConfiguration, str]) -> None
        IUserConfiguration.__init__(self)

        self._username = ''          # type: str
        self._password = None        # type: Optional[str]
        self._server = ''            # type: Optional[str]
        self._last_device = None     # type: Optional[UserDeviceConfiguration]
        if isinstance(user, str):
            self._username = adjust_username(user)
        elif isinstance(user, IUserConfiguration):
            self._username = user.username
            self._password = user.password
            self._server = user.server
            ldc = user.last_device
            if ldc:
                self._last_device = UserDeviceConfiguration(ldc)

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):    # type: (str) -> None
        self._password = value

    @property
    def server(self):
        return self._server

    @server.setter
    def server(self, value):
        self._server = value

    @property
    def last_device(self):
        return self._last_device

    @last_device.setter
    def last_device(self, value):
        self._last_device = value


class ServerConfiguration(IServerConfiguration):
    def __init__(self, other):  # type: (Union[str, IServerConfiguration]) -> None
        IServerConfiguration.__init__(self)

        self._server = ''
        self._server_key_id = 1
        if isinstance(other, str):
            self._server = adjust_servername(other)
        elif isinstance(other, IServerConfiguration):
            self._server = other.server
            self._server_key_id = other.server_key_id

    @property
    def server(self):
        return self._server

    @property
    def server_key_id(self):
        return self._server_key_id

    @server_key_id.setter
    def server_key_id(self, value):
        self._server_key_id = value


class DeviceServerConfiguration(IDeviceServerConfiguration):
    def __init__(self, server):   # type: (Union[IDeviceServerConfiguration, str]) -> None
        IDeviceServerConfiguration.__init__(self)

        self._server = ''       # type: str
        self._clone_code = ''   # type: Optional[str]
        if isinstance(server, str):
            self._server = adjust_servername(server)
        elif isinstance(server, IDeviceServerConfiguration):
            self._server = server.server
            self._clone_code = server.clone_code

    @property
    def server(self):
        return self._server

    @property
    def clone_code(self):
        return self._clone_code

    @clone_code.setter
    def clone_code(self, value):
        self._clone_code = value


class DeviceConfiguration(IDeviceConfiguration):
    def __init__(self, device):    # type: (Union[IDeviceConfiguration, str]) -> None
        IDeviceConfiguration.__init__(self)

        self._device_token = ''
        self._private_key = ''
        self._public_key = ''
        self._server_info = ConfigurationCollection()
        if isinstance(device, str):
            self._device_token = device
        elif isinstance(device, IDeviceConfiguration):
            self._device_token = device.device_token
            self._private_key = device.private_key
            self._public_key = device.public_key
            src_server_info = device.get_server_info()
            dst_server_info = self.get_server_info()
            if src_server_info:
                for dsc in src_server_info.list():
                    dst_server_info.put(DeviceServerConfiguration(dsc))

    @property
    def device_token(self):
        return self._device_token

    @property
    def public_key(self):
        return self._public_key

    @public_key.setter
    def public_key(self, value):  # type: (str) -> None
        self._public_key = value

    @property
    def private_key(self):
        return self._private_key

    @private_key.setter
    def private_key(self, value):
        self._private_key = value

    def get_server_info(self):
        return self._server_info


class KeeperConfiguration(IKeeperConfiguration):
    def __init__(self, other=None):
        IKeeperConfiguration.__init__(self)

        self._last_login = ''
        self._last_server = ''
        self._users = ConfigurationCollection()
        self._devices = ConfigurationCollection()
        self._servers = ConfigurationCollection()
        if isinstance(other, IKeeperConfiguration):
            self._last_login = other.last_login
            self._last_server = other.last_server
            for uc in other.users().list():
                self.users().put(UserConfiguration(uc))
            for dc in other.devices().list():
                self.devices().put(DeviceConfiguration(dc))
            for sc in other.servers().list():
                self.servers().put(ServerConfiguration(sc))

    def users(self):
        return self._users

    def servers(self):
        return self._servers

    def devices(self):
        return self._devices

    @property
    def last_login(self):
        return self._last_login

    @last_login.setter
    def last_login(self, value):
        self._last_login = value

    @property
    def last_server(self):
        return self._last_server

    @last_server.setter
    def last_server(self, value):
        self._last_server = value


class InMemoryConfigurationStorage(IConfigurationStorage):
    def __init__(self, configuration=None):
        super().__init__()
        self.configuration = configuration if isinstance(configuration, IKeeperConfiguration) else KeeperConfiguration()

    def get(self):
        return self.configuration
    
    def put(self, configuration):
        self.configuration = KeeperConfiguration(configuration)


class _JsonConfigurationCollection(list, IConfigurationCollection):
    def __init__(self, entity_type):   # type: (Union[Type[dict], Type[IEntityId]]) -> None
        super(_JsonConfigurationCollection, self).__init__()
        self.entity_type = entity_type

    def get(self, entity_id):
        idx = self._get_index(entity_id)
        if idx >= 0:
            return self[idx]

    def put(self, entity):
        entity_id = self._get_id(entity)
        if entity_id:
            idx = self._get_index(entity_id)
            json_entity = self.entity_type(entity)
            if idx >= 0:
                self[idx] = json_entity
            else:
                self.append(json_entity)

    def delete(self, entity_id):
        idx = self._get_index(entity_id)
        if idx >= 0:
            self.pop(idx)

    def list(self):
        return self

    @staticmethod
    def _get_id(entity):
        if isinstance(entity, IEntityId):
            return entity.get_id()

    def _get_index(self, entity_id):
        return next((i for i, x in enumerate(self) if self._get_id(x) == entity_id), -1)


class _JsonDeviceServerConfiguration(IDeviceServerConfiguration, dict):
    SERVER = 'server'
    CLONE_CODE = 'clone_code'

    def __init__(self, data):  # type: (Union[None, dict, IDeviceServerConfiguration]) -> None
        super(_JsonDeviceServerConfiguration, self).__init__()
        if isinstance(data, dict):
            self.update(data)
        elif isinstance(data, IDeviceServerConfiguration):
            self[self.SERVER] = data.server
            clone_code = data.clone_code
            if clone_code:
                self[self.CLONE_CODE] = clone_code

    @property
    def server(self):
        return self.get(self.SERVER)

    @property
    def clone_code(self):
        return self.get(self.CLONE_CODE)


class _JsonDeviceConfiguration(IDeviceConfiguration, dict):
    DEVICE_TOKEN = 'device_token'
    PUBLIC_KEY = 'public_key'
    PRIVATE_KEY = 'private_key'
    SERVER_INFO = 'server_info'

    def __init__(self, data):  # type: (Union[None, dict, IDeviceConfiguration]) -> None
        super(_JsonDeviceConfiguration, self).__init__()
        server_info = _JsonConfigurationCollection(_JsonDeviceServerConfiguration)
        if isinstance(data, dict):
            self.update(data)
            if self.SERVER_INFO in data and isinstance(data[self.SERVER_INFO], list):
                for si in data[self.SERVER_INFO]:
                    server_info.append(_JsonDeviceServerConfiguration(si))
        elif isinstance(data, IDeviceConfiguration):
            self[self.DEVICE_TOKEN] = data.device_token
            public_key = data.public_key
            if public_key:
                self[self.PUBLIC_KEY] = public_key
            private_key = data.private_key
            if private_key:
                self[self.PRIVATE_KEY] = private_key
            for dsc in data.get_server_info().list():
                server_info.append(_JsonDeviceServerConfiguration(dsc))
        self[self.SERVER_INFO] = server_info

    @property
    def device_token(self):
        return self.get(self.DEVICE_TOKEN)

    @property
    def public_key(self):
        return self.get(self.PUBLIC_KEY)

    @property
    def private_key(self):
        return self.get(self.PRIVATE_KEY)

    def get_server_info(self):
        return self.get(self.SERVER_INFO)


class _JsonServerConfiguration(IServerConfiguration, dict):
    SERVER = 'server'
    SERVER_KEY_ID = 'server_key_id'

    def __init__(self, data=None):   # type: (Union[None, dict, IServerConfiguration]) -> None
        super(_JsonServerConfiguration, self).__init__()
        if isinstance(data, dict):
            self.update(data)
        if isinstance(data, IServerConfiguration):
            self[self.SERVER] = data.server
            self[self.SERVER_KEY_ID] = data.server_key_id

    @property
    def server(self):
        return self.get(self.SERVER, '')

    @property
    def server_key_id(self):
        return self.get(self.SERVER_KEY_ID, 1)


class _JsonUserDeviceConfiguration(IUserDeviceConfiguration, dict):
    DEVICE_TOKEN = 'device_token'

    def __init__(self, data=None):  # type: (Union[None, dict, IUserDeviceConfiguration]) -> None
        super(_JsonUserDeviceConfiguration, self).__init__()
        if isinstance(data, dict):
            self.update(data)
        elif isinstance(data, IUserDeviceConfiguration):
            self[self.DEVICE_TOKEN] = data.device_token

    @property
    def device_token(self):
        return self.get(self.DEVICE_TOKEN)


class _JsonUserConfiguration(IUserConfiguration, dict):
    USER = 'user'
    PASSWORD = 'password'
    SERVER = 'server'
    LAST_DEVICE = 'last_device'
    SECURED = 'secured'

    def __init__(self, data=None):   # type: (Union[None, dict, IUserConfiguration]) -> None
        super(_JsonUserConfiguration, self).__init__()
        if isinstance(data, dict):
            self.update(data)
            if self.LAST_DEVICE in self:
                self[self.LAST_DEVICE] = _JsonUserDeviceConfiguration(self[self.LAST_DEVICE])

        elif isinstance(data, IUserConfiguration):
            self[self.USER] = data.username
            password = data.password
            if password:
                self[self.PASSWORD] = password
            server = data.server
            if server:
                self[self.SERVER] = data.server
            last_device = data.last_device
            if last_device:
                self[self.LAST_DEVICE] = _JsonUserDeviceConfiguration(last_device)

    @property
    def username(self):
        return self.get(self.USER)

    @property
    def password(self):
        return self.get(self.PASSWORD)

    @property
    def server(self):
        return self.get(self.SERVER)

    @property
    def last_device(self):
        return self.get(self.LAST_DEVICE)


class _JsonKeeperConfiguration(dict, IKeeperConfiguration):
    LAST_SERVER = 'last_server'
    LAST_LOGIN = 'last_login'
    USERS = 'users'
    SERVERS = 'servers'
    DEVICES = 'devices'

    def __init__(self):
        super(_JsonKeeperConfiguration, self).__init__()
        self[self.USERS] = _JsonConfigurationCollection(_JsonUserConfiguration)
        self[self.SERVERS] = _JsonConfigurationCollection(_JsonServerConfiguration)
        self[self.DEVICES] = _JsonConfigurationCollection(_JsonDeviceConfiguration)

    @property
    def last_login(self):
        return self.get(self.LAST_LOGIN)

    @last_login.setter
    def last_login(self, value):
        if value:
            self[self.LAST_LOGIN] = value
        else:
            self.pop(self.LAST_LOGIN, None)

    @property
    def last_server(self):
        return self.get(self.LAST_SERVER)

    @last_server.setter
    def last_server(self, value):
        if value:
            self[self.LAST_SERVER] = value
        else:
            self.pop(self.LAST_SERVER, None)

    def users(self):
        return self[self.USERS]

    def servers(self):
        return self[self.SERVERS]

    def devices(self):
        return self[self.DEVICES]


class IJsonLoader(abc.ABC):
    @abc.abstractmethod
    def load_json(self):   # type: () -> bytes
        pass

    @abc.abstractmethod
    def store_json(self, data):   # type: (bytes) -> None
        pass


class JsonFileLoader(IJsonLoader):
    def __init__(self, file_name=None):  # type: (Optional[str]) -> None
        IJsonLoader.__init__(self)
        if not file_name:
            file_name = 'login.json'
        if os.path.isfile(file_name):
            self.file_path = os.path.abspath(file_name)
        else:
            keeper_dir = os.path.join(os.path.expanduser('~'), '.keeper')
            if not os.path.exists(keeper_dir):
                os.mkdir(keeper_dir)
            self.file_path = os.path.join(keeper_dir, file_name)

    def load_json(self):
        with open(self.file_path, 'rb') as f:
            return f.read()

    def store_json(self, data):
        with open(self.file_path, 'wb') as f:
            f.write(data)


class JsonConfigurationStorage(IConfigurationStorage):
    def __init__(self, loader=None, file_name=None):  # type: (Optional[IJsonLoader], Optional[str]) -> None
        IConfigurationStorage.__init__(self)
        if not loader:
            loader = JsonFileLoader(file_name or 'login.json')
        self.loader = loader

    def put(self, configuration):
        logger = utils.get_logger()
        if not isinstance(configuration, IKeeperConfiguration):
            logger.warning('Store JSON configuration: Invalid configuration')
            return

        if not isinstance(configuration, _JsonKeeperConfiguration):
            json_storage = _JsonKeeperConfiguration()
            json_storage.assign(configuration)
            configuration = json_storage

        self.loader.store_json(json.dumps(configuration, indent=2).encode())

    def get(self):
        logger = utils.get_logger()
        data = self.loader.load_json()
        json_conf = {}
        if data:
            with io.BytesIO(data) as fp:
                try:
                    json_conf = json.load(fp)
                except Exception as e:
                    logger.debug('Load JSON configuration', exc_info=e)

        storage = _JsonKeeperConfiguration()
        storage.last_login = json_conf.get(_JsonKeeperConfiguration.LAST_LOGIN)
        storage.last_server = json_conf.get(_JsonKeeperConfiguration.LAST_SERVER)
        json_users = json_conf.get(_JsonKeeperConfiguration.USERS)
        if isinstance(json_users, list):
            users = storage.users()
            for user in json_users:
                if isinstance(user, dict):
                    users.put(_JsonUserConfiguration(user))

        json_servers = json_conf.get(_JsonKeeperConfiguration.SERVERS)
        if isinstance(json_servers, list):
            servers = storage.servers()
            for server in json_servers:
                if isinstance(server, dict):
                    servers.put(_JsonServerConfiguration(server))

        json_devices = json_conf.get(_JsonKeeperConfiguration.DEVICES)
        if isinstance(json_devices, list):
            devices = storage.devices()
            for device in json_devices:
                if isinstance(device, dict):
                    devices.put(_JsonDeviceConfiguration(device))

        return storage
