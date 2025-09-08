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
import logging

from ..utils.constants import SUCCESS_MESSAGES, ERROR_MESSAGES
from ..commands.base import BiometricArgparseCommand, CommandError
from ...params import KeeperParams


class BiometricRegisterCommand(BiometricArgparseCommand):
    """Register biometric authentication"""
    def __init__(self):
        parser = argparse.ArgumentParser(prog='biometric register', description='Add biometric authentication method')
        parser.add_argument('--name', dest='name', action='store', 
                       help='Friendly name for the biometric method')
        super().__init__(parser)

    # def get_parser(self):
    #     return self.parser

    def execute(self, context: KeeperParams, **kwargs):
        """Execute registration with improved error handling and method breakdown"""
        def _register():
            username = context.username
            self._validate_prerequisites(username, kwargs)
            registration_data = self._prepare_registration(kwargs)
            credential = self._perform_registration(context, registration_data)
            self._finalize_registration(username, credential)
        
        return self._execute_with_error_handling('register biometric authentication', _register)

    def _validate_prerequisites(self, username: str, kwargs):
        """Validate platform support and check for existing credentials"""
        self._check_platform_support(kwargs.get('force', False))
        self._check_existing_credentials(username=username)

    def _check_existing_credentials(self, username: str):
        """Check if credential already exists for this user"""
        if self.client.platform_handler and hasattr(self.client.platform_handler, 'storage_handler'):
            storage_handler = getattr(self.client.platform_handler, 'storage_handler')
            if storage_handler and hasattr(storage_handler, 'get_credential_id'):
                existing_credential_id = storage_handler.get_credential_id(username)
                if existing_credential_id:
                    raise CommandError(ERROR_MESSAGES['credential_already_registered'])

    def _prepare_registration(self, kwargs):
        """Prepare registration data and options"""
        friendly_name = kwargs.get('name') or self._get_default_credential_name()
        
        if len(friendly_name) > 32:
            raise ValueError("Friendly name must be 32 characters or less")
        
        logging.info("Adding biometric authentication method: %s", friendly_name)
        
        return {
            'friendly_name': friendly_name
        }

    def _perform_registration(self, context: KeeperParams, registration_data):
        """Perform the actual biometric registration"""
        try:
            # Generate registration options
            registration_options = self.client.generate_registration_options(context.vault)
            
            # Create credential
            credential_response = self.client.create_credential(registration_options)
            
            # Verify registration
            self.client.verify_registration(context, registration_options, credential_response, registration_data['friendly_name'])
            
            return {
                'response': credential_response,
                'friendly_name': registration_data['friendly_name']
            }
            
        except Exception as e:
            return self._handle_registration_error(e, context.username, registration_data['friendly_name'])

    def _handle_registration_error(self, error, username, friendly_name):
        """Handle registration errors, including existing credential scenarios"""
        error_str = str(error).lower()
        if ("object already exists" in error_str or 
            "biometric credential for this account already exists" in error_str):
            
            self._store_placeholder_credential(username)
            return {'friendly_name': friendly_name, 'existing_credential': True}
        else:
            raise error

    def _store_placeholder_credential(self, username: str):
        """Store placeholder credential ID if storage is available"""
        if self.client.platform_handler and hasattr(self.client.platform_handler, 'storage_handler'):
            storage_handler = getattr(self.client.platform_handler, 'storage_handler')
            if storage_handler and hasattr(storage_handler, 'store_credential_id'):
                existing_credential_id = storage_handler.get_credential_id(username)
                if not existing_credential_id:
                    placeholder_id = f"{username}"
                    storage_handler.store_credential_id(username, placeholder_id)
                    logging.debug("Stored placeholder credential ID for user: %s", username)
                else:
                    logging.debug("Credential ID already exists for user: %s", username)

    def _finalize_registration(self, username: str, credential):
        """Finalize registration and report success"""
        friendly_name = credential['friendly_name']
        self._report_success(friendly_name, username)

    def _report_success(self, friendly_name: str, username: str):
        """Report successful registration"""
        if self._check_biometric_flag(username):
            logging.info(SUCCESS_MESSAGES['registration_complete'])
            print(f'\nSuccess! Biometric authentication "{friendly_name}" has been registered.')
            print(f'\nPlease register your device using the \033[31m"this-device register"\033[0m command to set biometric authentication as your default login method.')
        else:
            print(f'\nBiometric authentication setup incomplete. Please try again.')        