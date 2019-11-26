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

import copy
import logging
import json
import os.path

from .utils import base64_url_decode, base64_url_encode
from .endpoint import DEFAULT_KEEPER_SERVER

from urllib.parse import urlparse


class UserConfiguration:
    def __init__(self, username, password=None, two_factor_token=None):
        self.username = UserConfiguration.adjust_name(username or '')
        self.password = password
        self.two_factor_token = two_factor_token

    @staticmethod
    def adjust_name(username):
        return username.lower() if username else ''


class ServerConfiguration:
    def __init__(self, server, device_id=None, server_key_id=1):
        self.server = ServerConfiguration.adjust_name(server)
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
            user = UserConfiguration(username)
            self.users.append(user)
        user.two_factor_token = user_config.two_factor_token

    def merge_server_configuration(self, server_config):
        host_name = ServerConfiguration.adjust_name(server_config.server)
        servers = [x for x in self.servers if ServerConfiguration.adjust_name(x.server) == host_name]
        if servers:
            server = servers[0]
        else:
            server = ServerConfiguration(host_name)
            self.servers.append(server)
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


class InMemoryConfigurationStorage:
    def __init__(self, configuration=None):
        self._configuration = configuration if configuration else Configuration()

    def get_configuration(self):
        return copy.copy(self._configuration)

    def put_configuration(self, configuration):
        if configuration is not self._configuration:
            self._configuration.clear()
            self._configuration.merge_configuration(configuration)


class JsonConfigurationStorage:
    def __init__(self, filename):
        if os.path.isfile(filename):
            self._file_path = os.path.abspath(filename)
        else:
            keeper_dir = os.path.join(os.path.expanduser('~'), '.keeper')
            if not os.path.exists(keeper_dir):
                os.mkdir(keeper_dir)
            self._file_path = os.path.join(keeper_dir, filename)

    @staticmethod
    def config_to_json(config, json_config):
        if config.last_username:
            json_config['last_login'] = config.last_username
        if config.last_server:
            json_config['last_server'] = config.last_server
        if config.users:
            cache = {}
            if 'users' in json_config and type(json_config['users']) is list:
                for user in json_config['users']:
                    if type(user) is dict and 'user' in user:
                        cache[UserConfiguration.adjust_name(user['user'])] = user
            else:
                json_config['users'] = []

            for user in config.users:
                if user.username:
                    username = user.username
                    json_user = cache.get(UserConfiguration.adjust_name(username))
                    if not json_user:
                        json_user = {
                            'user': username
                        }
                        cache[username] = json_user
                        json_config['users'].append(json_user)
                    json_user['mfa_token'] = user.two_factor_token
        if config.servers:
            cache = {}
            if 'servers' in json_config and type(json_config['servers']) is list:
                for server in json_config['servers']:
                    if type(server) is dict and 'server' in server:
                        cache[ServerConfiguration.adjust_name(server['server'])] = server
            for server in config.servers:
                if server.server:
                    host_name = ServerConfiguration.adjust_name(server.server)
                    json_server = cache.get(host_name)
                    if json_server is None:
                        json_server = {
                            'server': host_name
                        }
                        cache[host_name] = json_server
                        json_config['servers'].append(json_server)
                    if server.device_id:
                        json_server['device_id'] = base64_url_encode(server.device_id)
                    if server.server_key_id:
                        json_server['server_key_id'] = server.server_key_id

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
        stored_config = {}
        try:
            if os.path.isfile(self._file_path):
                with open(self._file_path, 'r') as fp:
                    stored_config = json.load(fp)
        except Exception as e:
            logging.error('Load JSON configuration error: %s', e)

        self.config_to_json(configuration, stored_config)
        try:
            with open(self._file_path, 'w') as fp:
                json.dump(stored_config, fp, ensure_ascii=False, indent=2)
                logging.debug('Stored JSON configuration')
        except Exception as e:
            logging.error('JSON configuration store error: %s', e)
