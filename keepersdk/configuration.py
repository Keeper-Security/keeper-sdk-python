#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2019 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import abc
import copy
import logging
import json
import os.path

from .utils import base64_url_decode, base64_url_encode
from .endpoint import DEFAULT_KEEPER_SERVER

from urllib.parse import urlparse


class UserConfiguration:
    def __init__(self, username=None, password=None, two_factor_token=None):
        self.username = username or ''
        self.password = password
        self.two_factor_token = two_factor_token

    @staticmethod
    def adjust_name(username):
        return username.lower() if username else ''


class ServerConfiguration:
    def __init__(self, server=None, device_id=None, server_key_id=1):
        self.server = server
        self.device_id = device_id
        self.server_key_id = server_key_id

    @staticmethod
    def adjust_name(server):
        if server:
            url = urlparse(server)
            if url.netloc:
                return url.netloc.lower()
            if url.path:
                return url.path.lower()
        return DEFAULT_KEEPER_SERVER


class Configuration:
    def __init__(self):
        self.users = []
        self.servers = []
        self.last_username = None
        self.last_server = None

    def clear(self):
        self.users.clear()
        self.servers.clear()
        self.last_server = None
        self.last_username = None

    def merge_user_configuration(self, user_config):
        username = UserConfiguration.adjust_name(user_config.username)
        users = [x for x in self.users if UserConfiguration.adjust_name(x.username) == username]
        if users:
            user = users[0]
        else:
            user = UserConfiguration()
            self.users.append(user)
        user.username = username
        if user.password:    # don't store password unless it's already stored
            user.password = user_config.password
        user.two_factor_token = user_config.two_factor_token

    def merge_server_configuration(self, server_config):
        host_name = ServerConfiguration.adjust_name(server_config.server)
        servers = [x for x in self.servers if ServerConfiguration.adjust_name(x.server) == host_name]
        if servers:
            server = servers[0]
        else:
            server = ServerConfiguration()
            self.servers.append(server)
        server.server = host_name
        server.device_id = server_config.device_id
        server.server_key_id = server_config.server_key_id

    def merge_configuration(self, configuration):
        self.last_server = configuration.last_server
        self.last_username = configuration.last_username
        for user in configuration.users:
            self.merge_user_configuration(user)
        for server in configuration.servers:
            self.merge_server_configuration(server)

    def get_user_configuration(self, username):
        aun = UserConfiguration.adjust_name(username)
        for user in self.users:
            if ServerConfiguration.adjust_name(user.username) == aun:
                return user
        return None

    def get_server_configuration(self, server):
        asn = UserConfiguration.adjust_name(server)
        for server in self.servers:
            if ServerConfiguration.adjust_name(server.server) == asn:
                return server
        return None


class IConfigurationStorage(abc.ABC):
    @abc.abstractmethod
    def get_configuration(self):
        pass

    @abc.abstractmethod
    def put_configuration(self, configuration):
        pass


class InMemoryConfiguration(IConfigurationStorage):
    def __init__(self, configuration=None):
        self._configuration = configuration if configuration else Configuration()

    def get_configuration(self):
        return copy.copy(self._configuration)

    def put_configuration(self, configuration):
        if configuration is not self._configuration:
            self._configuration.clear()
            self._configuration.merge_configuration(configuration)


class JsonConfiguration(IConfigurationStorage):
    def __init__(self, filename):
        if os.path.isfile(filename):
            self._file_path = os.path.abspath(filename)
        else:
            keeper_dir = os.path.join(os.path.expanduser('~'), '.keeper')
            if not os.path.exists(keeper_dir):
                os.mkdir(keeper_dir)
            self._file_path = os.path.join(keeper_dir, filename)

    @staticmethod
    def config_to_json(config):
        json_config = {}
        if config.last_username:
            json_config['last_login'] = config.last_username
        if config.last_server:
            json_config['last_server'] = config.last_server
        if config.users:
            json_config['users'] = []
            for user in config.users:
                if user.username:
                    json_user = {
                        'user': user.username
                    }
                    json_config['users'].append(json_user)
                    if user.password:
                        json_user['password'] = user.password
                    if user.two_factor_token:
                        json_user['mfa_token'] = user.two_factor_token
        if config.servers:
            json_config['servers'] = []
            for server in config.servers:
                if server.server:
                    json_server = {
                        'server': server.server
                    }
                    json_config['servers'].append(json_server)
                    if server.device_id:
                        json_server['device_id'] = base64_url_encode(server.device_id)
                    if server.server_key_id:
                        json_server['server_key_id'] = server.server_key_id
        return json_config

    @staticmethod
    def json_to_config(json_config):
        config = Configuration()
        if 'last_login' in json_config:
            config.last_username = json_config['last_login']
        if 'last_server' in json_config:
            config.last_server = json_config['last_server']
        if 'users' in json_config:
            for user in json_config['users']:
                user_conf = UserConfiguration(user.get('user'), user.get('password'), user.get('mfa_token'))
                config.users.append(user_conf)
        if 'servers' in json_config:
            for server in json_config['servers']:
                server_url = server.get('server')
                device_id = None
                if 'device_id' in server:
                    device_id = base64_url_decode(server['device_id'])
                server_key_id = server.get('server_key_id') or 1
                server_conf = ServerConfiguration(server_url, device_id, server_key_id)
                config.servers.append(server_conf)
        return config

    def get_configuration(self):
        try:
            if os.path.isfile(self._file_path):
                with open(self._file_path, 'r') as fp:
                    return self.json_to_config(json.load(fp))
        except Exception as e:
            logging.error('Load JSON configuration error: %s', e)
        return Configuration()

    def put_configuration(self, configuration):
        conf = self.get_configuration()
        conf.merge_configuration(configuration)
        json_config = self.config_to_json(conf)
        try:
            with open(self._file_path, 'w') as fp:
                json.dump(json_config, fp, ensure_ascii=False, indent=2)
                logging.debug('Stored JSON configuration')
        except Exception as e:
            logging.error('JSON configuration store error: %s', e)
