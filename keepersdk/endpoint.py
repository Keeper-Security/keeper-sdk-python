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
import json
import logging
import locale

from requests import post
from urllib.parse import urlunparse

from . import crypto, utils
from .errors import KeeperApiError
from .APIRequest_pb2 import (NewUserMinimumParams, ApiRequestPayload, ApiRequest, DeviceRequest,
                             DeviceResponse, DeviceStatus, AuthRequest)

DEFAULT_KEEPER_SERVER = 'keepersecurity.com'


class KeeperEndpoint:
    def __init__(self):
        self.client_version = CLIENT_VERSION
        self.device_name = DEFAULT_DEVICE_NAME
        self.locale = resolve_locale()
        self.transmission_key = None
        self.server = DEFAULT_KEEPER_SERVER
        self.server_key_id = 1
        self.encrypted_device_token = None

    def execute_rest(self, endpoint, payload):

        run_request = True
        while run_request:
            run_request = False

            if not (1 <= self.server_key_id <= 6):
                self.server_key_id = 1
            if not self.transmission_key:
                self.transmission_key = crypto.get_random_bytes(32)
            server_public_key = SERVER_PUBLIC_KEYS[self.server_key_id]
            encrypted_transmission_key = crypto.encrypt_rsa(self.transmission_key, server_public_key)

            api_request = ApiRequest()
            api_request.encryptedTransmissionKey = encrypted_transmission_key
            api_request.publicKeyId = self.server_key_id
            api_request.locale = self.locale
            api_request.encryptedPayload = crypto.encrypt_aes_v2(payload.SerializeToString(), self.transmission_key)

            request_data = api_request.SerializeToString()

            url_comp = ('https', self.server, 'api/rest/' + endpoint, None, None, None)
            url = urlunparse(url_comp)
            logging.debug('>>> Request URL: [%s]', url)

            headers = {
                'Content-Type': 'application/octet-stream',
                'User-Agent': 'KeeperSDK.Python/' + self.client_version
            }
            rs = post(url, data=request_data, headers=headers)
            logging.debug('<<< Response Code: [%d]', rs.status_code)
            logging.debug('<<< Response Headers: [%s]', str(rs.headers))

            content_type = rs.headers.get('Content-Type') or ''
            if rs.status_code == 200:
                if content_type == 'application/json':
                    return rs.json()
                else:
                    return crypto.decrypt_aes_v2(rs.content, self.transmission_key)
            elif rs.status_code >= 400:
                failure = rs.json() if content_type == 'application/json' else None
                if rs.status_code == 401 and failure:
                    if 'error' in failure:
                        if failure['error'] == 'key':
                            server_key_id = failure['key_id']
                            if server_key_id != self.server_key_id:
                                self.server_key_id = server_key_id
                                run_request = True
                                continue

                if logging.getLogger().level <= logging.DEBUG:
                    if rs.text:
                        logging.debug('<<< Response Content: [%s]', str(rs.text))

                return failure

    def get_device_token(self):
        if not self.encrypted_device_token:
            rq = DeviceRequest()
            rq.clientVersion = self.client_version
            rq.deviceName = self.device_name

            payload = ApiRequestPayload()
            payload.payload = rq.SerializeToString()
            rs = self.execute_rest('authentication/get_device_token', payload)
            if type(rs) == bytes:
                device_rs = DeviceResponse()
                device_rs.ParseFromString(rs)
                if DeviceStatus.Name(device_rs.status) == 'OK':
                    self.encrypted_device_token = device_rs.encryptedDeviceToken
            elif type(rs) == dict:
                raise KeeperApiError(rs['error'], rs['message'])
        return self.encrypted_device_token

    def get_new_user_params(self, username):
        rq = AuthRequest()
        rq.clientVersion = CLIENT_VERSION
        rq.username = username.lower()
        rq.encryptedDeviceToken = self.get_device_token()

        payload = ApiRequestPayload()
        payload.payload = rq.SerializeToString()
        rs = self.execute_rest('authentication/get_new_user_params', payload)
        if type(rs) == bytes:
            pre_login_rs = NewUserMinimumParams()
            pre_login_rs.ParseFromString(rs)
            return pre_login_rs

        raise KeeperApiError(rs['error'], rs['message'])

    def v2_execute(self, rq):
        if 'client_version' not in rq:
            rq['client_version'] = self.client_version
        logging.debug('>>> Request JSON: [%s]', json.dumps(rq, sort_keys=True, indent=4))
        rq_data = json.dumps(rq).encode('utf-8')

        payload = ApiRequestPayload()
        payload.payload = rq_data
        rs_data = self.execute_rest('vault/execute_v2_command', payload)
        rs = json.loads(rs_data.decode('utf-8'))
        logging.debug('<<< Response JSON: [%s]', json.dumps(rs, sort_keys=True, indent=4))

        return rs


DEFAULT_DEVICE_NAME = 'Python Keeper API'

CLIENT_VERSION = 'c14.0.0'

SERVER_PUBLIC_KEYS = {
    1: crypto.load_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEA9Z_CZzxiNUz8-npqI4V10-zW3AL7-M4UQDdd_17759Xzm0MOEfH' +
        'OOsOgZxxNK1DEsbyCTCE05fd3Hz1mn1uGjXvm5HnN2mL_3TOVxyLU6VwH9EDInn' +
        'j4DNMFifs69il3KlviT3llRgPCcjF4xrF8d4SR0_N3eqS1f9CBJPNEKEH-am5Xb' +
        '_FqAlOUoXkILF0UYxA_jNLoWBSq-1W58e4xDI0p0GuP0lN8f97HBtfB7ijbtF-V' +
        'xIXtxRy-4jA49zK-CQrGmWqIm5DzZcBvUtVGZ3UXd6LeMXMJOifvuCneGC2T2uB' +
        '6G2g5yD54-onmKIETyNX0LtpR1MsZmKLgru5ugwIDAQAB')),

    2: crypto.load_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEAkOpym7xC3sSysw5DAidLoVF7JUgnvXejbieDWmEiD-DQOKxzfQq' +
        'YHoFfeeix__bx3wMW3I8cAc8zwZ1JO8hyB2ON732JE2Zp301GAUMnAK_rBhQWmY' +
        'KP_-uXSKeTJPiuaW9PVG0oRJ4MEdS-t1vIA4eDPhI1EexHaY3P2wHKoV8twcGvd' +
        'WUZB5gxEpMbx5CuvEXptnXEJlxKou3TZu9uwJIo0pgqVLUgRpW1RSRipgutpUsl' +
        'BnQ72Bdbsry0KKVTlcPsudAnnWUtsMJNgmyQbESPm-aVv-GzdVUFvWKpKkAxDpN' +
        'ArPMf0xt8VL2frw2LDe5_n9IMFogUiSYt156_mQIDAQAB')),

    3: crypto.load_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEAyvxCWbLvtMRmq57oFg3mY4DWfkb1dir7b29E8UcwcKDcCsGTqoI' +
        'hubU2pO46TVUXmFgC4E-Zlxt-9F-YA-MY7i_5GrDvySwAy4nbDhRL6Z0kz-rqUi' +
        'rgm9WWsP9v-X_BwzARqq83HNBuzAjf3UHgYDsKmCCarVAzRplZdT3Q5rnNiYPYS' +
        'HzwfUhKEAyXk71UdtleD-bsMAmwnuYHLhDHiT279An_Ta93c9MTqa_Tq2Eirl_N' +
        'Xn1RdtbNohmMXldAH-C8uIh3Sz8erS4hZFSdUG1WlDsKpyRouNPQ3diorbO88wE' +
        'AgpHjXkOLj63d1fYJBFG0yfu73U80aEZehQkSawIDAQAB')),

    4: crypto.load_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEA0TVoXLpgluaqw3P011zFPSIzWhUMBqXT-Ocjy8NKjJbdrbs53eR' +
        'FKk1waeB3hNn5JEKNVSNbUIe-MjacB9P34iCfKtdnrdDB8JXx0nIbIPzLtcJC4H' +
        'CYASpjX_TVXrU9BgeCE3NUtnIxjHDy8PCbJyAS_Pv299Q_wpLWnkkjq70ZJ2_fX' +
        '-ObbQaZHwsWKbRZ_5sD6rLfxNACTGI_jo9-vVug6AdNq96J7nUdYV1cG-INQwJJ' +
        'KMcAbKQcLrml8CMPc2mmf0KQ5MbS_KSbLXHUF-81AsZVHfQRSuigOStQKxgSGL5' +
        'osY4NrEcODbEXtkuDrKNMsZYhijKiUHBj9vvgKwIDAQAB')),

    5: crypto.load_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEAueOWC26w-HlOLW7s88WeWkXpjxK4mkjqngIzwbjnsU9145R51Hv' +
        'sILvjXJNdAuueVDHj3OOtQjfUM6eMMLr-3kaPv68y4FNusvB49uKc5ETI0HtHmH' +
        'FSn9qAZvC7dQHSpYqC2TeCus-xKeUciQ5AmSfwpNtwzM6Oh2TO45zAqSA-QBSk_' +
        'uv9TJu0e1W1AlNmizQtHX6je-mvqZCVHkzGFSQWQ8DBL9dHjviI2mmWfL_egAVV' +
        'hBgTFXRHg5OmJbbPoHj217Yh-kHYA8IWEAHylboH6CVBdrNL4Na0fracQVTm-nO' +
        'WdM95dKk3fH-KJYk_SmwB47ndWACLLi5epLl9vwIDAQAB')),

    6: crypto.load_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEA2PJRM7-4R97rHwY_zCkFA8B3llawb6gF7oAZCpxprl6KB5z2cqL' +
        'AvUfEOBtnr7RIturX04p3ThnwaFnAR7ADVZWBGOYuAyaLzGHDI5mvs8D-NewG9v' +
        'w8qRkTT7Mb8fuOHC6-_lTp9AF2OA2H4QYiT1vt43KbuD0Y2CCVrOTKzDMXG8msl' +
        '_JvAKt4axY9RGUtBbv0NmpkBCjLZri5AaTMgjLdu8XBXCqoLx7qZL-Bwiv4njw-' +
        'ZAI4jIszJTdGzMtoQ0zL7LBj_TDUBI4Qhf2bZTZlUSL3xeDWOKmd8Frksw3oKyJ' +
        '17oCQK-EGau6EaJRGyasBXl8uOEWmYYgqOWirNwIDAQAB')),
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


def resolve_locale():
    system_locale = locale.getdefaultlocale()
    if system_locale[0] in KEEPER_LANGUAGES:
        return KEEPER_LANGUAGES[system_locale[0]]
    if system_locale[0] in KEEPER_LANGUAGES.values():
        return system_locale[0]
    return 'en_US'
