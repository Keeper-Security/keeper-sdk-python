import abc
import json
import os
import threading
from typing import Optional, Any, Dict

from fido2.client import ClientError, DefaultClientDataCollector, UserInteraction, WebAuthnClient
from fido2.ctap import CtapError
from fido2.hid import CtapHidDevice
from fido2.webauthn import PublicKeyCredentialRequestOptions, UserVerificationRequirement, AuthenticationResponse
from .. import utils

class IKeeperUserInteraction(abc.ABC):
    @abc.abstractmethod
    def output_text(self, text: str) -> None:
        pass

def verify_rp_id_none(rp_id, origin):
    return True

def yubikey_authenticate(request: Dict[str, Any], user_interaction: UserInteraction) -> Optional[str]:
    logger = utils.get_logger()

    if 'publicKeyCredentialRequestOptions' not in request:  # WebAuthN
        logger.warning('Invalid Security Key request')
        return None

    origin = ''
    options = request['publicKeyCredentialRequestOptions']

    if 'extensions' in options:
        extensions = options['extensions']
        origin = extensions.get('appid') or ''
        if 'largeBlob' not in options['extensions']:
            options['extensions']['largeBlob'] = {'read': None}

    credentials = options.get('allowCredentials') or []
    for c in credentials:
        if isinstance(c.get('id'), str):
            c['id'] = utils.base64_url_decode(c['id'])

    challenge = options['challenge']
    if isinstance(challenge, str):
        options['challenge'] = utils.base64_url_decode(challenge)

    client = None   # type: Optional[WebAuthnClient]
    data_collector = DefaultClientDataCollector(origin, verify=verify_rp_id_none)
    if os.name == 'nt':
        from fido2.client.windows import WindowsClient
        client = WindowsClient(client_data_collector=data_collector)
    else:
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            logger.warning("No Security Key detected")
            return None
        from fido2.client import Fido2Client
        fido_client = Fido2Client(dev, client_data_collector=data_collector, user_interaction=user_interaction)
        uv_configured = any(fido_client.info.options.get(k) for k in ("uv", "clientPin", "bioEnroll"))
        if not uv_configured:
            uv = options['userVerification']
            if uv == UserVerificationRequirement.PREFERRED:
                options['userVerification'] = UserVerificationRequirement.DISCOURAGED
        client = fido_client

    evt= threading.Event()
    response: Optional[AuthenticationResponse] = None
    try:
        try:
            rq_options = PublicKeyCredentialRequestOptions.from_dict(options)
            rs = client.get_assertion(rq_options, event=evt)
            response = rs.get_response(0)
        except ClientError as err:
            if isinstance(err.cause, CtapError):
                if err.cause.code == CtapError.ERR.NO_CREDENTIALS:
                    if user_interaction and isinstance(user_interaction, IKeeperUserInteraction):
                        user_interaction.output_text('\n\nKeeper Security stopped supporting U2F security keys starting February 2022.\n'
                              'If you registered your security key prior to this date please re-register it within the Web Vault.\n'
                              'For information on using security keys with Keeper see the documentation: \n'
                              'https://docs.keeper.io/enterprise-guide/two-factor-authentication#security-keys-fido-webauthn\n'
                              'Commander will use the fallback security key authentication method.\n\n'
                              'To use your Yubikey with Commander, please touch the flashing Security key one more time.\n')
                    options['rpId'] = origin
                    rq_options = PublicKeyCredentialRequestOptions.from_dict(options)
                    rs = client.get_assertion(rq_options, event=evt)
                    response = rs.get_response(0)
                elif err.cause.code == CtapError.ERR.PIN_INVALID:
                    raise Exception('PIN is invalid')
                elif err.cause.code == CtapError.ERR.PIN_AUTH_BLOCKED:
                    raise Exception('PIN is blocked')
            elif isinstance(err.cause, str):
                if err.code == ClientError.ERR.CONFIGURATION_UNSUPPORTED:
                    raise Exception('Security key user verification (PIN or Biometric) is not configured')
            raise err
        except KeyboardInterrupt:
            pass
    finally:
        evt.set()

    if response:
        extensions = dict(response.client_extension_results) if response.client_extension_results else {}
        signature = {
            "id": response.id,
            "rawId": utils.base64_url_encode(response.raw_id),
            "response": {
                "authenticatorData": utils.base64_url_encode(response.response.authenticator_data),
                "clientDataJSON": response.response.client_data.b64,
                "signature": utils.base64_url_encode(response.response.signature),
            },
            "type": "public-key",
            "clientExtensionResults": extensions
        }
        return json.dumps(signature)
    return None
