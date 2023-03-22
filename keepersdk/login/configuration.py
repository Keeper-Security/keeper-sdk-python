#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com        self._remove_indexes(to_remove)class _
#

import abc
import io
import json
import os
from typing import Type, Union
from urllib.parse import urlparse

from .endpoint import DEFAULT_KEEPER_SERVER
from .. import utils


def adjust_username(username):
    return username.lower() if isinstance(username, str) else ''


def adjust_servername(server):
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
    def get_id(self):
        pass


class IUserConfiguration(IEntityId):
    def __init__(self):
        super(IUserConfiguration, self).__init__()
        
    @abc.abstractmethod
    def get_username(self):
        pass

    @abc.abstractmethod
    def get_password(self):
        pass

    @abc.abstractmethod
    def get_server(self):
        pass

    @abc.abstractmethod
    def get_last_device(self):
        pass

    def get_id(self):
        return self.get_username()


class IServerConfiguration(IEntityId):
    def __init__(self):
        super(IServerConfiguration, self).__init__()

    @abc.abstractmethod
    def get_server(self):
        pass

    @abc.abstractmethod
    def get_server_key_id(self):
        pass

    def get_id(self):
        return self.get_server()


class IDeviceServerConfiguration(IEntityId):
    def __init__(self):
        super(IDeviceServerConfiguration, self).__init__()

    @abc.abstractmethod
    def get_server(self):
        pass

    @abc.abstractmethod
    def get_clone_code(self):
        pass

    def get_id(self):
        return self.get_server()


class IDeviceConfiguration(IEntityId):
    def __init__(self):
        super(IDeviceConfiguration, self).__init__()

    @abc.abstractmethod
    def get_device_token(self):
        pass

    @abc.abstractmethod
    def get_public_key(self):
        pass

    @abc.abstractmethod
    def get_private_key(self):
        pass

    @abc.abstractmethod
    def get_server_info(self):
        pass

    def get_id(self):
        return self.get_device_token()


class IUserDeviceConfiguration(IEntityId):
    def __init__(self):
        super(IUserDeviceConfiguration, self).__init__()

    @abc.abstractmethod
    def get_device_token(self):
        pass

    def get_id(self):
        return self.get_device_token()


class IConfigurationCollection(abc.ABC):
    def __init__(self):
        super(IConfigurationCollection, self).__init__()

    @abc.abstractmethod
    def get(self, entity_id):
        pass

    @abc.abstractmethod
    def put(self, entity):
        pass

    @abc.abstractmethod
    def delete(self, entity_id):
        pass

    @abc.abstractmethod
    def list(self):
        pass


class IKeeperConfiguration(abc.ABC):
    def __init__(self):
        super(IKeeperConfiguration, self).__init__()

    @abc.abstractmethod
    def users(self):
        pass

    @abc.abstractmethod
    def servers(self):
        pass

    @abc.abstractmethod
    def devices(self):
        pass

    @abc.abstractmethod
    def get_last_login(self):
        pass

    @abc.abstractmethod
    def set_last_login(self, value):
        pass

    @abc.abstractmethod
    def get_last_server(self):
        pass

    @abc.abstractmethod
    def set_last_server(self, value):
        pass

    def assign(self, other):
        user_ids = [x.get_id() for x in self.users().list()]
        for user_id in user_ids:
            self.users().delete(user_id)
        server_ids = [x.get_id() for x in self.servers().list()]
        for server_id in server_ids:
            self.servers().delete(server_id)
        device_ids = [x.get_id() for x in self.devices().list()]
        for device_id in device_ids:
            self.devices().delete(device_id)

        self.set_last_login(other.get_last_login())
        self.set_last_server(other.get_last_server())
        for user in other.users().list():
            self.users().put(user)
        for server in other.servers().list():
            self.servers().put(server)
        for device in other.devices().list():
            self.devices().put(device)


class IConfigurationStorage(abc.ABC):
    def __init__(self):
        super(IConfigurationStorage, self).__init__()

    @abc.abstractmethod
    def get(self):
        pass

    @abc.abstractmethod
    def put(self, configuration):
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
    def __init__(self, user_device):
        IUserDeviceConfiguration.__init__(self)

        self._device_token = ''
        if isinstance(user_device, str):
            self._device_token = user_device
        elif isinstance(user_device, IUserDeviceConfiguration):
            self._device_token = user_device.get_device_token()

    def get_device_token(self):
        return self._device_token


class UserConfiguration(IUserConfiguration):
    def __init__(self, user):
        IUserConfiguration.__init__(self)

        self._username = ''
        self._password = None
        self._server = ''
        self._last_device = None
        if isinstance(user, str):
            self._username = adjust_username(user)
        elif isinstance(user, IUserConfiguration):
            self._username = user.get_username()
            self._password = user.get_password()
            self._server = user.get_server()
            ldc = user.get_last_device()
            if ldc:
                self._last_device = UserDeviceConfiguration(ldc)

    def get_username(self):
        return self._username

    def get_password(self):
        return self._password

    def get_server(self):
        return self._server

    def get_last_device(self):
        return self._last_device

    def set_password(self, value):
        self._password = value

    def set_server(self, value):
        self._server = value

    def set_last_device(self, value):
        self._last_device = value

    password = property(get_password, set_password)
    server = property(get_server, set_server)
    last_device = property(get_last_device, set_last_device)


class ServerConfiguration(IServerConfiguration):
    def __init__(self, server):
        IServerConfiguration.__init__(self)

        self._server = ''
        self._server_key_id = 1
        if isinstance(server, str):
            self._server = adjust_servername(server)
        elif isinstance(server, IServerConfiguration):
            self._server = server.get_server()
            self._server_key_id = server.get_server_key_id()

    def get_server(self):
        return self._server

    def get_server_key_id(self):
        return self._server_key_id

    def set_server_key_id(self, value):
        self._server_key_id = value

    server_key_id = property(get_server_key_id, set_server_key_id)


class DeviceServerConfiguration(IDeviceServerConfiguration):
    def __init__(self, server):
        IDeviceServerConfiguration.__init__(self)

        self._server = ''
        self._clone_code = ''
        if isinstance(server, str):
            self._server = adjust_servername(server)
        elif isinstance(server, IDeviceServerConfiguration):
            self._server = server.get_server()
            self._clone_code = server.get_clone_code()

    def get_server(self):
        return self._server

    def get_clone_code(self):
        return self._clone_code

    def set_clone_code(self, value):
        self._clone_code = value

    clone_code = property(get_clone_code, set_clone_code)


class DeviceConfiguration(IDeviceConfiguration):
    def __init__(self, device):
        IDeviceConfiguration.__init__(self)

        self._device_token = ''
        self._private_key = ''
        self._public_key = ''
        self._server_info = ConfigurationCollection()
        if isinstance(device, str):
            self._device_token = device
        elif isinstance(device, IDeviceConfiguration):
            self._device_token = device.get_device_token()
            self._private_key = device.get_private_key()
            self._public_key = device.get_public_key()
            src_server_info = device.get_server_info()
            dst_server_info = self.get_server_info()
            if src_server_info:
                for dsc in src_server_info.list():
                    dst_server_info.put(DeviceServerConfiguration(dsc))

    def get_device_token(self):
        return self._device_token

    def get_public_key(self):
        return self._public_key

    def get_private_key(self):
        return self._private_key

    def get_server_info(self):
        return self._server_info

    def set_public_key(self, value):
        self._public_key = value

    def set_private_key(self, value):
        self._private_key = value

    public_key = property(get_public_key, set_public_key)
    private_key = property(get_private_key, set_private_key)


class KeeperConfiguration(IKeeperConfiguration):
    def __init__(self, other=None):
        IKeeperConfiguration.__init__(self)

        self._last_login = ''
        self._last_server = ''
        self._users = ConfigurationCollection()
        self._devices = ConfigurationCollection()
        self._servers = ConfigurationCollection()
        if isinstance(other, IKeeperConfiguration):
            self._last_login = other.get_last_login()
            self._last_server = other.get_last_server()
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

    def get_last_login(self):
        return self._last_login

    def set_last_login(self, value):
        self._last_login = value

    def get_last_server(self):
        return self._last_server

    def set_last_server(self, value):
        self._last_server = value

    last_login = property(get_last_login, set_last_login)
    last_server = property(get_last_server, set_last_server)


class InMemoryConfigurationStorage(IConfigurationStorage):
    def __init__(self, configuration: KeeperConfiguration):
        self.configuration = configuration or KeeperConfiguration()

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
            self[self.SERVER] = data.get_server()
            clone_code = data.get_clone_code()
            if clone_code:
                self[self.CLONE_CODE] = clone_code

    def get_server(self):
        return self.get(self.SERVER)

    def get_clone_code(self):
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
            self[self.DEVICE_TOKEN] = data.get_device_token()
            public_key = data.get_public_key()
            if public_key:
                self[self.PUBLIC_KEY] = public_key
            private_key = data.get_private_key()
            if private_key:
                self[self.PRIVATE_KEY] = private_key
            for si in data.get_server_info().list():  # type: IDeviceServerConfiguration
                server_info.append(_JsonDeviceServerConfiguration(si))
        self[self.SERVER_INFO] = server_info

    def get_device_token(self):
        return self.get(self.DEVICE_TOKEN)

    def get_public_key(self):
        return self.get(self.PUBLIC_KEY)

    def get_private_key(self):
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
            self[self.SERVER] = data.get_server()
            self[self.SERVER_KEY_ID] = data.get_server_key_id()

    def get_server(self):
        return self.get(self.SERVER, '')

    def get_server_key_id(self):
        return self.get(self.SERVER_KEY_ID, 1)


class _JsonUserDeviceConfiguration(IUserDeviceConfiguration, dict):
    DEVICE_TOKEN = 'device_token'

    def __init__(self, data=None):  # type: (Union[None, dict, IUserDeviceConfiguration]) -> None
        super(_JsonUserDeviceConfiguration, self).__init__()
        if isinstance(data, dict):
            self.update(data)
        elif isinstance(data, IUserDeviceConfiguration):
            self[self.DEVICE_TOKEN] = data.get_device_token()

    def get_device_token(self):
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
            self[self.USER] = data.get_username()
            password = data.get_password()
            if password:
                self[self.PASSWORD] = password
            server = data.get_server()
            if server:
                self[self.SERVER] = data.get_server()
            last_device = data.get_last_device()
            if last_device:
                self[self.LAST_DEVICE] = _JsonUserDeviceConfiguration(last_device)

    def get_username(self):
        return self.get(self.USER)

    def get_password(self):
        return self.get(self.PASSWORD)

    def get_server(self):
        return self.get(self.SERVER)

    def get_last_device(self):
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

    def get_last_login(self):
        return self.get(self.LAST_LOGIN)

    def set_last_login(self, value):
        if value:
            self[self.LAST_LOGIN] = value
        else:
            self.pop(self.LAST_LOGIN, None)

    def get_last_server(self):
        return self.get(self.LAST_SERVER)

    def set_last_server(self, value):
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
    def load_json(self):
        pass

    @abc.abstractmethod
    def store_json(self, data):
        pass


class JsonFileLoader(IJsonLoader):
    def __init__(self, file_name=None):
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
    def __init__(self, loader=None, file_name=None):
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
        storage.set_last_login(json_conf.get(_JsonKeeperConfiguration.LAST_LOGIN))
        storage.set_last_server(json_conf.get(_JsonKeeperConfiguration.LAST_SERVER))
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
