#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import json
from typing import Optional, Dict, Any, Union

from keepersdk.authentication import login_auth

from ..commands.base import BiometricArgparseCommand
from ..utils.constants import SUCCESS_MESSAGES, API_ENDPOINTS
from ...params import KeeperParams
from keepersdk import utils
from keepersdk.proto import APIRequest_pb2
from keepersdk.vault import vault_online


class BiometricVerifyCommand(BiometricArgparseCommand):
    """Verify biometric authentication"""
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='biometric verify', description='Verify biometric authentication with existing credentials'
        )
        parser.add_argument(
            '--purpose', dest='purpose', choices=['login', 'vault'], default='login', 
            help='Authentication purpose (default: login)'
        )
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        """Execute biometric verify command"""
        def _verify():
            self._check_platform_support()
            purpose = kwargs.get('purpose', 'login')

            available_credentials = self._get_available_credentials_or_error(context.vault)

            # Generate authentication options
            auth_options = self.client.generate_authentication_options(context, purpose)

            # Perform authentication
            assertion_response = self.client.perform_authentication(auth_options)

            # Verify authentication
            verification_result = self._verify_authentication_response(
                context.vault, auth_options, assertion_response, purpose)

            # Report results
            self._report_verification_results(verification_result, purpose)

        return self._execute_with_error_handling('verify biometric authentication', _verify)

    def _verify_authentication_response(self, 
        auth_context: Union[vault_online.VaultOnline, login_auth.LoginAuth], 
        auth_options: Dict[str, Any], 
        assertion_response: Any, 
        purpose: str
    ) -> Union[Dict[str, Any], APIRequest_pb2.PasskeyValidationResponse]:
        """Verify the authentication response with Keeper"""
        try:
            actual_response = self._extract_assertion_response(assertion_response)

            if not hasattr(actual_response, 'response'):
                raise ValueError(f"Invalid assertion response object: {type(actual_response)}")

            client_data_bytes = actual_response.response.client_data
            client_data_b64 = self._extract_client_data_b64(client_data_bytes)

            if not actual_response.id or not actual_response.raw_id:
                raise ValueError("Could not extract credential ID from assertion response")

            assertion_object = self._create_assertion_object(actual_response, client_data_b64)

            # Determine if this is a vault or login authentication
            if isinstance(auth_context, vault_online.VaultOnline):
                return self._send_verification_request(
                    auth_context, auth_options, assertion_object, purpose)
            else:
                return self._send_login_verification_request(
                    auth_context, auth_options, assertion_object, purpose)

        except (ValueError, AttributeError) as e:
            raise ValueError(f"Authentication verification failed: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error during authentication verification: {str(e)}")

    def _extract_client_data_b64(self, client_data_bytes: Any) -> str:
        """Extract base64-encoded client data"""
        if hasattr(client_data_bytes, 'b64'):
            return client_data_bytes.b64
        elif isinstance(client_data_bytes, bytes):
            return utils.base64_url_encode(client_data_bytes)
        else:
            return str(client_data_bytes)

    def _create_assertion_object(self, actual_response: Any, client_data_b64: str) -> Dict[str, Any]:
        """Create assertion object for verification"""
        return {
            'id': actual_response.id,
            'rawId': utils.base64_url_encode(actual_response.raw_id),
            'response': {
                'authenticatorData': utils.base64_url_encode(actual_response.response.authenticator_data),
                'clientDataJSON': client_data_b64,
                'signature': utils.base64_url_encode(actual_response.response.signature),
            },
            'type': 'public-key',
            'clientExtensionResults': getattr(actual_response, 'client_extension_results', {}) or {}
        }

    def _send_verification_request(
        self, 
        vault: vault_online.VaultOnline, 
        auth_options: Dict[str, Any], 
        assertion_object: Dict[str, Any], 
        purpose: str
    ) -> Dict[str, Any]:
        """Send verification request to Keeper API"""

        rq = APIRequest_pb2.PasskeyValidationRequest()
        rq.challengeToken = auth_options['challenge_token']
        rq.assertionResponse = json.dumps(assertion_object).encode('utf-8')
        rq.passkeyPurpose = (APIRequest_pb2.PasskeyPurpose.PK_REAUTH 
                           if purpose == 'vault' else APIRequest_pb2.PasskeyPurpose.PK_LOGIN)

        if auth_options.get('login_token'):
            login_token = auth_options['login_token']
            rq.encryptedLoginToken = utils.base64_url_decode(login_token) if isinstance(login_token, str) else login_token

        rs = vault.keeper_auth.execute_auth_rest(rest_endpoint=API_ENDPOINTS['verify_authentication'], request=rq, response_type=APIRequest_pb2.PasskeyValidationResponse)

        return {
            'is_valid': rs.isValid,
            'login_token': rs.encryptedLoginToken,
            'credential_id': assertion_object['id'].encode() if isinstance(assertion_object['id'], str) else assertion_object['id'],
            'user_handle': self._extract_user_handle(assertion_object)
        }

    def _send_login_verification_request(
        self, 
        login_auth: login_auth.LoginAuth, 
        auth_options: Dict[str, Any], 
        assertion_object: Dict[str, Any], 
        purpose: str
    ) -> APIRequest_pb2.PasskeyValidationResponse:
        """Send verification request to Keeper API"""

        rq = APIRequest_pb2.PasskeyValidationRequest()
        rq.challengeToken = auth_options['challenge_token']
        rq.assertionResponse = json.dumps(assertion_object).encode('utf-8')
        rq.passkeyPurpose = (APIRequest_pb2.PasskeyPurpose.PK_REAUTH 
                           if purpose == 'vault' else APIRequest_pb2.PasskeyPurpose.PK_LOGIN)

        if auth_options.get('login_token'):
            login_token = auth_options['login_token']
            rq.encryptedLoginToken = utils.base64_url_decode(login_token) if isinstance(login_token, str) else login_token

        rs = login_auth.execute_rest(rest_endpoint=API_ENDPOINTS['verify_authentication'], request=rq, response_type=APIRequest_pb2.PasskeyValidationResponse)

        return rs

    def _extract_user_handle(self, assertion_object: Dict[str, Any]) -> Optional[Any]:
        """Extract user handle from assertion object safely"""
        try:
            response = assertion_object.get('response', {})
            if isinstance(response, dict):
                return response.get('user_handle')
            return None
        except (AttributeError, KeyError):
            return None

    def _extract_assertion_response(self, assertion_result: Any) -> Any:
        """Extract assertion response from various result types"""
        try:
            if hasattr(assertion_result, 'get_response'):
                response = assertion_result.get_response(0)
                if response is None:
                    raise ValueError("No response found in assertion result")
                return response
            elif hasattr(assertion_result, 'get_assertions'):
                assertions = assertion_result.get_assertions()
                if not assertions:
                    raise ValueError("AssertionSelection has no assertions")
                return assertions[0]
            elif hasattr(assertion_result, 'response'):
                return assertion_result
            elif hasattr(assertion_result, 'assertions') and assertion_result.assertions:
                return assertion_result.assertions[0]
            else:
                raise ValueError(f"Unknown assertion result format: {type(assertion_result)}")
        except (ValueError, AttributeError) as e:
            raise ValueError(f"Failed to extract assertion response: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error extracting assertion response: {str(e)}")

    def _report_verification_results(self, verification_result: Dict[str, Any], purpose: str) -> None:
        """Report the verification results to the user"""
        logger = utils.get_logger()
        logger.info(f"\nBiometric Authentication Verification Results:")
        logger.info("=" * 50)

        if verification_result['is_valid']:
            logger.info("Status: SUCCESSFUL")
            logger.info(f"Purpose: {purpose.upper()}")

            if verification_result.get('user_handle'):
                logger.info(f"User Handle: {utils.base64_url_encode(verification_result['user_handle'])}")
            if verification_result.get('login_token'):
                logger.info("Login Token: Received")

            logger.info(f"\n{SUCCESS_MESSAGES['verification_success']}")
        else:
            logger.info("Status: FAILED")
            logger.info(f"Purpose: {purpose.upper()}")
            logger.info("\n  Authentication verification failed. Please check your biometric setup.")

        logger.info("=" * 50)

    def biometric_authenticate(
        self, login_auth: login_auth.LoginAuth, client_version: str, username: str, 
        purpose: str = 'login', device_token: Optional[str] = None
    ) -> Union[Dict[str, Any], APIRequest_pb2.PasskeyValidationResponse]:
        """Perform biometric authentication for login"""
        try:
            auth_options = self.client.generate_login_authentication_options(login_auth, client_version, username, purpose, device_token)
            assertion_response = self.client.perform_authentication(auth_options)
            verification_result = self._verify_authentication_response(login_auth, auth_options, assertion_response, purpose)

            return verification_result

        except (ValueError, RuntimeError) as e:
            raise RuntimeError(f"Biometric authentication failed: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error during biometric authentication: {str(e)}") 