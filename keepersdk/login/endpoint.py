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

import json
import logging
import locale
import requests

from typing import Optional, Dict, Any
from urllib.parse import urlunparse
from google.protobuf.json_format import MessageToJson

from . import configuration, notifications
from .. import crypto, utils
from ..proto import APIRequest_pb2

from .. import errors

DEFAULT_KEEPER_SERVER = 'keepersecurity.com'
DEFAULT_DEVICE_NAME = 'Python Keeper API'
CLIENT_VERSION = 'c16.5.0'


def prepare_api_request(key_id, transmission_key, payload=None, session_token=None, keeper_locale=None):
    # type: (int, bytes, Optional[bytes], Optional[bytes], Optional[str]) -> APIRequest_pb2.ApiRequest
    api_payload = APIRequest_pb2.ApiRequestPayload()
    api_payload.apiVersion = 3
    if session_token:
        api_payload.encryptedSessionToken = session_token
    if payload:
        api_payload.payload = payload

    enc_payload = crypto.encrypt_aes_v2(api_payload.SerializeToString(), transmission_key)
    enc_transmission_key = encrypt_with_keeper_key(transmission_key, key_id)
    api_request = APIRequest_pb2.ApiRequest()
    api_request.encryptedTransmissionKey = enc_transmission_key
    api_request.publicKeyId = key_id
    api_request.encryptedPayload = enc_payload
    api_request.locale = keeper_locale or 'en_US'

    return api_request


def encrypt_with_keeper_key(data, key_id):
    # type: (bytes, int) -> bytes
    if 1 <= key_id <= 6:
        return crypto.encrypt_rsa(data, SERVER_PUBLIC_KEYS[key_id])
    elif 7 <= key_id <= 17:
        return crypto.encrypt_ec(data, SERVER_PUBLIC_KEYS[key_id])
    else:
        raise errors.KeeperApiError('invalid_key_id', f'Key ID \"{key_id}\" is not valid.')


class KeeperEndpoint:
    def __init__(self, storage, server=None):
        # type: (configuration.IConfigurationStorage, Optional[str]) -> None
        self.client_version = CLIENT_VERSION     # type: str
        self.device_name = DEFAULT_DEVICE_NAME   # type: str
        self.locale = resolve_locale()           # type: str
        self._server = ''                        # type: str
        self._server_key_id = 1                  # type: int
        self._storage = storage                  # type: configuration.IConfigurationStorage
        self._transmission_key = utils.generate_aes_key()  # type: bytes
        if not server:
            config = storage.get()
            server = config.get_last_server()
        self.server = server or DEFAULT_KEEPER_SERVER

    def set_server(self, server):   # type: (str) -> None
        config = self._storage.get()
        server = configuration.adjust_servername(server)
        sc = config.servers().get(server)
        if sc:
            self._server = sc.get_server()
            self._server_key_id = sc.get_server_key_id()
        else:
            self._server = server
            self._server_key_id = None

    def get_server(self):  # type: () -> str
        return self._server or DEFAULT_KEEPER_SERVER

    server = property(get_server, set_server)

    def get_server_key_id(self):  # type: () -> int
        return self._server_key_id or 1

    def get_configuration_storage(self):  # type: () -> configuration.IConfigurationStorage
        return self._storage

    def get_push_server(self):  # type: () -> str
        return f'push.services.{self.server}'

    def _communicate_keeper(self, endpoint, payload, session_token=None):
        # type: (str, bytes, Optional[bytes]) -> bytes
        logger = utils.get_logger()

        key_id = self.get_server_key_id()
        attempt = 0
        while attempt < 3:
            attempt += 1

            api_request = prepare_api_request(key_id, self._transmission_key, payload, session_token, self.locale)

            if endpoint.startswith('https://'):
                url = endpoint
            else:
                url_comp = ('https', self.server, 'api/rest/' + endpoint, None, None, None)
                url = urlunparse(url_comp)
            logger.debug('>>> Request URL: [%s]', url)

            headers = {
                'Content-Type': 'application/octet-stream',
                'User-Agent': 'KeeperSDK.Python/' + self.client_version
            }
            rs = requests.post(url, data=api_request.SerializeToString(), headers=headers)
            logger.debug('<<< Response Code: [%d]', rs.status_code)

            content_type = rs.headers.get('Content-Type') or ''
            if rs.status_code == 200:
                if key_id != self._server_key_id:
                    self._server_key_id = key_id
                    config = self._storage.get()
                    sc = configuration.ServerConfiguration(self.get_server())
                    sc.server_key_id = key_id
                    config.servers().put(sc)
                    self._storage.put(config)

                rs_body = rs.content
                return crypto.decrypt_aes_v2(rs_body, self._transmission_key) if rs_body else None
            elif content_type == 'application/json':
                error_rs = rs.json()
                if 'error' in error_rs:
                    error_code = error_rs['error']
                    error_message = error_rs.get('message') or error_rs.get('additional_info')
                    if error_code == 'key':
                        if 'key_id' in error_rs:
                            key_id = error_rs['key_id']
                            continue
                    elif error_code == 'region_redirect':
                        raise errors.RegionRedirectError(error_rs['region_host'], error_message)
                    elif error_code == 'device_not_registered':
                        raise errors.InvalidDeviceTokenError(error_message)
                    elif error_code in {'session_token', 'auth_failed'}:
                        raise errors.AuthFailedError(error_message)
                    raise errors.KeeperApiError(error_code, error_message)

            raise errors.KeeperError(f'HTTP Status Code: {rs.status_code}')

        raise errors.KeeperError('Failed to execute Keeper API request')

    def execute_rest(self, rest_endpoint, request, response_type=None, session_token=None):
        logger = utils.get_logger()
        if logger.level <= logging.DEBUG:
            js = MessageToJson(request) if request else ''
            logger.debug('>>> [RQ] \"%s\": %s', rest_endpoint, js)

        rs_data = self._communicate_keeper(
            endpoint=rest_endpoint, payload=request.SerializeToString() if request else None,
            session_token=session_token)
        if rs_data and response_type:
            rs = response_type()
            rs.ParseFromString(rs_data)
            if logger.level <= logging.DEBUG:
                js = MessageToJson(rs)
                logger.debug('>>> [RS] \"%s\": %s', rest_endpoint, js)

            return rs

    def v2_execute(self, command, session_token=None):
        # type: (Dict[str, Any], Optional[bytes]) -> Optional[Dict[str, Any]]
        logger = utils.get_logger()

        if 'client_version' not in command:
            command['client_version'] = self.client_version
        if session_token:
            command['session_token'] = utils.base64_url_encode(session_token)

        rq_data = json.dumps(command, sort_keys=True, indent=4)
        if logger.level <= logging.DEBUG:
            logger.debug('>>> [RQ]: %s', rq_data)
        rs_data = self._communicate_keeper(endpoint='vault/execute_v2_command', payload=rq_data.encode('utf-8'),
                                           session_token=session_token)
        if rs_data:
            rs_str = rs_data.decode('utf-8')
            if logger.level <= logging.DEBUG:
                logger.debug('<<< [RS]: %s', rs_str)
            rs = json.loads(rs_str)
            return rs

    def connect_to_push_server(self, payload):  # type: (bytes) -> notifications.KeeperPushNotifications
        transmission_key = utils.generate_aes_key()
        api_rq = prepare_api_request(self.get_server_key_id(), transmission_key, payload)

        push_server = self.get_push_server()
        url_comp = ('wss', push_server, '/wss_open_connection/' + utils.base64_url_encode(api_rq.SerializeToString()),
                    None, None, None)
        push_url = urlunparse(url_comp)

        keeper_pushes = notifications.KeeperPushNotifications(transmission_key)
        keeper_pushes.connect_to_push_channel(push_url)
        return keeper_pushes


SERVER_PUBLIC_KEYS = {
    1: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEA9Z_CZzxiNUz8-npqI4V10-zW3AL7-M4UQDdd_17759Xzm0MOEfH' +
        'OOsOgZxxNK1DEsbyCTCE05fd3Hz1mn1uGjXvm5HnN2mL_3TOVxyLU6VwH9EDInn' +
        'j4DNMFifs69il3KlviT3llRgPCcjF4xrF8d4SR0_N3eqS1f9CBJPNEKEH-am5Xb' +
        '_FqAlOUoXkILF0UYxA_jNLoWBSq-1W58e4xDI0p0GuP0lN8f97HBtfB7ijbtF-V' +
        'xIXtxRy-4jA49zK-CQrGmWqIm5DzZcBvUtVGZ3UXd6LeMXMJOifvuCneGC2T2uB' +
        '6G2g5yD54-onmKIETyNX0LtpR1MsZmKLgru5ugwIDAQAB')),

    2: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEAkOpym7xC3sSysw5DAidLoVF7JUgnvXejbieDWmEiD-DQOKxzfQq' +
        'YHoFfeeix__bx3wMW3I8cAc8zwZ1JO8hyB2ON732JE2Zp301GAUMnAK_rBhQWmY' +
        'KP_-uXSKeTJPiuaW9PVG0oRJ4MEdS-t1vIA4eDPhI1EexHaY3P2wHKoV8twcGvd' +
        'WUZB5gxEpMbx5CuvEXptnXEJlxKou3TZu9uwJIo0pgqVLUgRpW1RSRipgutpUsl' +
        'BnQ72Bdbsry0KKVTlcPsudAnnWUtsMJNgmyQbESPm-aVv-GzdVUFvWKpKkAxDpN' +
        'ArPMf0xt8VL2frw2LDe5_n9IMFogUiSYt156_mQIDAQAB')),

    3: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEAyvxCWbLvtMRmq57oFg3mY4DWfkb1dir7b29E8UcwcKDcCsGTqoI' +
        'hubU2pO46TVUXmFgC4E-Zlxt-9F-YA-MY7i_5GrDvySwAy4nbDhRL6Z0kz-rqUi' +
        'rgm9WWsP9v-X_BwzARqq83HNBuzAjf3UHgYDsKmCCarVAzRplZdT3Q5rnNiYPYS' +
        'HzwfUhKEAyXk71UdtleD-bsMAmwnuYHLhDHiT279An_Ta93c9MTqa_Tq2Eirl_N' +
        'Xn1RdtbNohmMXldAH-C8uIh3Sz8erS4hZFSdUG1WlDsKpyRouNPQ3diorbO88wE' +
        'AgpHjXkOLj63d1fYJBFG0yfu73U80aEZehQkSawIDAQAB')),

    4: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEA0TVoXLpgluaqw3P011zFPSIzWhUMBqXT-Ocjy8NKjJbdrbs53eR' +
        'FKk1waeB3hNn5JEKNVSNbUIe-MjacB9P34iCfKtdnrdDB8JXx0nIbIPzLtcJC4H' +
        'CYASpjX_TVXrU9BgeCE3NUtnIxjHDy8PCbJyAS_Pv299Q_wpLWnkkjq70ZJ2_fX' +
        '-ObbQaZHwsWKbRZ_5sD6rLfxNACTGI_jo9-vVug6AdNq96J7nUdYV1cG-INQwJJ' +
        'KMcAbKQcLrml8CMPc2mmf0KQ5MbS_KSbLXHUF-81AsZVHfQRSuigOStQKxgSGL5' +
        'osY4NrEcODbEXtkuDrKNMsZYhijKiUHBj9vvgKwIDAQAB')),

    5: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEAueOWC26w-HlOLW7s88WeWkXpjxK4mkjqngIzwbjnsU9145R51Hv' +
        'sILvjXJNdAuueVDHj3OOtQjfUM6eMMLr-3kaPv68y4FNusvB49uKc5ETI0HtHmH' +
        'FSn9qAZvC7dQHSpYqC2TeCus-xKeUciQ5AmSfwpNtwzM6Oh2TO45zAqSA-QBSk_' +
        'uv9TJu0e1W1AlNmizQtHX6je-mvqZCVHkzGFSQWQ8DBL9dHjviI2mmWfL_egAVV' +
        'hBgTFXRHg5OmJbbPoHj217Yh-kHYA8IWEAHylboH6CVBdrNL4Na0fracQVTm-nO' +
        'WdM95dKk3fH-KJYk_SmwB47ndWACLLi5epLl9vwIDAQAB')),

    6: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEA2PJRM7-4R97rHwY_zCkFA8B3llawb6gF7oAZCpxprl6KB5z2cqL' +
        'AvUfEOBtnr7RIturX04p3ThnwaFnAR7ADVZWBGOYuAyaLzGHDI5mvs8D-NewG9v' +
        'w8qRkTT7Mb8fuOHC6-_lTp9AF2OA2H4QYiT1vt43KbuD0Y2CCVrOTKzDMXG8msl' +
        '_JvAKt4axY9RGUtBbv0NmpkBCjLZri5AaTMgjLdu8XBXCqoLx7qZL-Bwiv4njw-' +
        'ZAI4jIszJTdGzMtoQ0zL7LBj_TDUBI4Qhf2bZTZlUSL3xeDWOKmd8Frksw3oKyJ' +
        '17oCQK-EGau6EaJRGyasBXl8uOEWmYYgqOWirNwIDAQAB')),

    7: crypto.load_ec_public_key(utils.base64_url_decode(
        'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM')),

    8: crypto.load_ec_public_key(utils.base64_url_decode(
        'BKnhy0obglZJK-igwthNLdknoSXRrGB-mvFRzyb_L-DKKefWjYdFD2888qN1ROczz4n3keYSfKz9Koj90Z6w_tQ')),

    9: crypto.load_ec_public_key(utils.base64_url_decode(
        'BAsPQdCpLIGXdWNLdAwx-3J5lNqUtKbaOMV56hUj8VzxE2USLHuHHuKDeno0ymJt-acxWV1xPlBfNUShhRTR77g')),

    10: crypto.load_ec_public_key(utils.base64_url_decode(
        'BNYIh_Sv03nRZUUJveE8d2mxKLIDXv654UbshaItHrCJhd6cT7pdZ_XwbdyxAOCWMkBb9AZ4t1XRCsM8-wkEBRg')),

    11: crypto.load_ec_public_key(utils.base64_url_decode(
        'BA6uNfeYSvqagwu4TOY6wFK4JyU5C200vJna0lH4PJ-SzGVXej8l9dElyQ58_ljfPs5Rq6zVVXpdDe8A7Y3WRhk')),

    12: crypto.load_ec_public_key(utils.base64_url_decode(
        'BMjTIlXfohI8TDymsHxo0DqYysCy7yZGJ80WhgOBR4QUd6LBDA6-_318a-jCGW96zxXKMm8clDTKpE8w75KG-FY')),

    13: crypto.load_ec_public_key(utils.base64_url_decode(
        'BJBDU1P1H21IwIdT2brKkPqbQR0Zl0TIHf7Bz_OO9jaNgIwydMkxt4GpBmkYoprZ_DHUGOrno2faB7pmTR7HhuI')),

    14: crypto.load_ec_public_key(utils.base64_url_decode(
        'BJFF8j-dH7pDEw_U347w2CBM6xYM8Dk5fPPAktjib-opOqzvvbsER-WDHM4ONCSBf9O_obAHzCyygxmtpktDuiE')),

    15: crypto.load_ec_public_key(utils.base64_url_decode(
        'BDKyWBvLbyZ-jMueORl3JwJnnEpCiZdN7yUvT0vOyjwpPBCDf6zfL4RWzvSkhAAFnwOni_1tQSl8dfXHbXqXsQ8')),

    16: crypto.load_ec_public_key(utils.base64_url_decode(
        'BDXyZZnrl0tc2jdC5I61JjwkjK2kr7uet9tZjt8StTiJTAQQmnVOYBgbtP08PWDbecxnHghx3kJ8QXq1XE68y8c')),

    17: crypto.load_ec_public_key(utils.base64_url_decode(
        'BFX68cb97m9_sweGdOVavFM3j5ot6gveg6xT4BtGahfGhKib-zdZyO9pwvv1cBda9ahkSzo1BQ4NVXp9qRyqVGU')),
}

KEEPER_LANGUAGES = {
    "ar": "ar_AE",
    "de": "de_DE",
    "el": "el_GR",
    "en-GB": "en_GB",
    "en": "en_US",
    "es": "es_ES",
    "fr": "fr_FR",
    "he": "iw_IL",
    "it": "it_IT",
    "ja": "ja_JP",
    "ko": "ko_KR",
    "nl": "nl_NL",
    "pl": "pl_PL",
    "pt": "pt_PT",
    "pt-BR": "pt_BR",
    "ro": "ro_RO",
    "ru": "ru_RU",
    "sk": "sk_SK",
    "zh": "zh_CN",
    "zh-HK": "zh_HK",
    "zh-TW": "zh_TW"
}


def resolve_locale():  # type: () -> str
    system_locale = locale.getdefaultlocale()
    if system_locale[0] in KEEPER_LANGUAGES:
        return KEEPER_LANGUAGES[system_locale[0]]
    if system_locale[0] in KEEPER_LANGUAGES.values():
        return system_locale[0]
    return 'en_US'
