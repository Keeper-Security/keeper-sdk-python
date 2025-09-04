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

from .commands.register import BiometricRegisterCommand
from .commands.list import BiometricListCommand
from .commands.unregister import BiometricUnregisterCommand
from .commands.verify import BiometricVerifyCommand
from .commands.update_name import BiometricUpdateNameCommand

from .client import BiometricClient
from .platforms.detector import BiometricDetector
from ..commands import base

def check_biometric_previously_used(username):
    """Check if biometric authentication was previously used for this user"""
    try:
        detector = BiometricDetector()
        handler = detector.get_platform_handler()
        return handler.get_biometric_flag(username)
    except Exception:
        return False

class BiometricCommand(base.GroupCommand):
    """Main biometric command group"""
    
    def __init__(self):
        super().__init__('biometric')
        self.register_command(BiometricRegisterCommand(), 'register')
        self.register_command(BiometricListCommand(), 'list')
        self.register_command(BiometricUnregisterCommand(),'unregister')
        self.register_command(BiometricVerifyCommand(), 'verify')
        self.register_command(BiometricUpdateNameCommand(), 'update-name')

__all__ = [
    'BiometricCommand',
    'BiometricRegisterCommand',
    'BiometricListCommand', 
    'BiometricUnregisterCommand',
    'BiometricVerifyCommand',
    'BiometricClient',
    'BiometricDetector',
    'check_biometric_previously_used',
]
