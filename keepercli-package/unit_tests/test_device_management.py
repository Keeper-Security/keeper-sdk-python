import unittest
from unittest.mock import MagicMock, patch

from keepercli.commands import device_management as cli_device_management
from keepercli.commands.device_management import (
    DeviceListCommand,
    DeviceLogoutCommand,
    DeviceRemoveCommand,
    DeviceRenameCommand,
)
from keepercli.commands import base
from keepersdk.authentication import device_management as sdk_device_management
from keepersdk.authentication.device_management import UserDeviceInfo
from keepersdk.proto import DeviceManagement_pb2


class DeviceManagementCommandTests(unittest.TestCase):
    def test_device_list_calls_sdk(self):
        cmd = DeviceListCommand()
        context = MagicMock()
        context.auth = MagicMock()

        with patch.object(
            sdk_device_management,
            'list_user_devices',
            return_value=[
                UserDeviceInfo(1, 'A', 'COMMANDER', 'LOGGED_IN', None),
            ],
        ) as mock_list:
            cmd.execute(context, format='json', output=None)
            mock_list.assert_called_once_with(context.auth)

    def test_device_logout_calls_sdk(self):
        cmd = DeviceLogoutCommand()
        context = MagicMock()
        context.auth = MagicMock()

        with patch.object(
            sdk_device_management,
            'logout_user_devices',
            return_value=['Laptop'],
        ) as mock_logout:
            cmd.execute(context, devices=['1'])
            mock_logout.assert_called_once_with(context.auth, ['1'])

    def test_device_list_requires_login(self):
        cmd = DeviceListCommand()
        context = MagicMock()
        context.auth = None
        with self.assertRaises(base.CommandError):
            cmd.execute(context)


if __name__ == '__main__':
    unittest.main()
