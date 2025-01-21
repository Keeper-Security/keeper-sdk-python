import threading
import time
from typing import Optional, Any, Dict

from fido2.client import Fido2Client, WindowsClient, ClientError, WebAuthnClient
from fido2.ctap import CtapError
from fido2.hid import CtapHidDevice
from fido2.webauthn import PublicKeyCredentialRequestOptions, UserVerificationRequirement, \
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponse

from keepersdk import utils
from . import api, prompt_utils


def verify_rp_id_none(rp_id, origin):
    return True


def yubikey_authenticate(request: Dict[str, Any]):
    logger = api.get_logger()

    if 'publicKeyCredentialRequestOptions' not in request:  # WebAuthN
        logger.warning('Invalid Security Key request')
        return

    origin = ''
    options = request['publicKeyCredentialRequestOptions']
    if 'extensions' in options:
        extensions = options['extensions']
        origin = extensions.get('appid') or ''

    credentials = options.get('allowCredentials') or []
    for c in credentials:
        if isinstance(c.get('id'), str):
            c['id'] = utils.base64_url_decode(c['id'])

    client: WebAuthnClient
    if WindowsClient.is_available():
        client = WindowsClient(origin, verify=verify_rp_id_none)
    else:
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            logger.warning("No Security Key detected")
            return
        client = Fido2Client(dev, origin, verify=verify_rp_id_none)

    evt: Optional[threading.Event] = threading.Event()
    response: Optional[AuthenticatorAssertionResponse] = None
    def auth_func():
        nonlocal response
        attempt = 0
        while attempt < 2:
            attempt += 1
            try:
                rq_options = PublicKeyCredentialRequestOptions(
                    utils.base64_url_decode(options['challenge']), rp_id=options['rpId'] if attempt == 0 else origin,
                    user_verification=options.get('userVerification', UserVerificationRequirement.DISCOURAGED),
                    allow_credentials=credentials)

                time.sleep(0.1)
                rs = client.get_assertion(rq_options, event=evt)
                response = rs.get_response(0)
                break
            except ClientError as err:
                if isinstance(err.cause, CtapError) and attempt == 1:
                    if err.cause.code == CtapError.ERR.NO_CREDENTIALS:
                        prompt_utils.output_text('\n\nKeeper Security stopped supporting U2F security keys starting February 2022.\n'
                              'If you registered your security key prior to this date please re-register it within the Web Vault.\n'
                              'For information on using security keys with Keeper see the documentation: \n'
                              'https://docs.keeper.io/enterprise-guide/two-factor-authentication#security-keys-fido-webauthn\n'
                              'Commander will use the fallback security key authentication method.\n\n'
                              'To use your Yubikey with Commander, please touch the flashing Security key one more time.\n')
                        continue
                raise err

    def func():
        nonlocal evt
        try:
            auth_func()
        except Exception as e:
            logger.debug('Yubikey auth error: %s', e)
        prompt_utils.cancel_input()

    th = threading.Thread(target=func)
    th.start()
    try:
        prompt = 'Touch the flashing Security key to authenticate or press Enter to resume with the primary two factor authentication...'
        prompt_utils.input_text(prompt)
    except KeyboardInterrupt:
        pass
    if evt:
        evt.set()
        evt = None
    th.join()

    return response
