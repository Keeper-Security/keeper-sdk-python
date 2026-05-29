import unittest
from unittest.mock import MagicMock

from keepercli.commands import device_management
from keepercli.commands.device_management import DeviceListCommand, DeviceRenameCommand
from keepercli.commands import base
from keepersdk.proto import DeviceManagement_pb2


def _device(name: str, last_modified: int = 0) -> DeviceManagement_pb2.Device:
    d = DeviceManagement_pb2.Device()
    d.deviceName = name
    d.lastModifiedTime = last_modified
    d.clientType = DeviceManagement_pb2.DESKTOP
    d.loginState = 0
    d.encryptedDeviceToken = b'\x01\x02'
    return d


class DeviceManagementCommandTests(unittest.TestCase):
    def test_device_list_calls_endpoint(self):
        cmd = DeviceListCommand()
        context = MagicMock()
        context.auth = MagicMock()

        rs = DeviceManagement_pb2.DeviceUserResponse()
        g = rs.deviceGroups.add()
        g.devices.append(_device('A', 100))
        context.auth.execute_auth_rest.return_value = rs

        cmd.execute(context, format='json', output=None)
        context.auth.execute_auth_rest.assert_called()
        args, kwargs = context.auth.execute_auth_rest.call_args
        self.assertEqual(kwargs.get('rest_endpoint'), 'dm/device_user_list')

    def test_device_rename_calls_rename_endpoint(self):
        cmd = DeviceRenameCommand()
        context = MagicMock()
        context.auth = MagicMock()

        list_rs = DeviceManagement_pb2.DeviceUserResponse()
        g = list_rs.deviceGroups.add()
        g.devices.append(_device('My Laptop', 100))

        rename_rs = DeviceManagement_pb2.DeviceRenameResponse()
        rr = rename_rs.deviceRenameResult.add()
        rr.deviceActionStatus = DeviceManagement_pb2.SUCCESS
        rr.deviceNewName = 'Renamed'
        rr.encryptedDeviceToken = b'\x01\x02'

        context.auth.execute_auth_rest.side_effect = [list_rs, rename_rs]

        cmd.execute(context, device='1', new_name='Renamed')
        self.assertEqual(context.auth.execute_auth_rest.call_count, 2)
        self.assertEqual(
            context.auth.execute_auth_rest.call_args_list[0].kwargs.get('rest_endpoint'),
            'dm/device_user_list'
        )
        self.assertEqual(
            context.auth.execute_auth_rest.call_args_list[1].kwargs.get('rest_endpoint'),
            'dm/device_user_rename'
        )

    def test_resolve_device_by_numeric_id(self):
        devices = [_device('Phone', 200), _device('Laptop', 100)]
        devices.sort(key=lambda d: d.lastModifiedTime or 0, reverse=True)
        resolved = device_management._resolve_device_identifier(devices, '2')
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[1].deviceName, 'Laptop')

    def test_resolve_device_by_unique_name_substring(self):
        devices = [_device('Work MacBook', 100), _device('Personal iPhone', 50)]
        resolved = device_management._resolve_device_identifier(devices, 'iphone')
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[1].deviceName, 'Personal iPhone')

    def test_resolve_device_ambiguous_name_returns_none(self):
        devices = [_device('MacBook Pro', 100), _device('MacBook Air', 90)]
        self.assertIsNone(device_management._resolve_device_identifier(devices, 'macbook'))

    def test_device_list_requires_login(self):
        cmd = DeviceListCommand()
        context = MagicMock()
        context.auth = None
        with self.assertRaises(base.CommandError):
            cmd.execute(context)

    def test_device_rename_rejects_empty_name(self):
        cmd = DeviceRenameCommand()
        context = MagicMock()
        context.auth = MagicMock()
        with self.assertRaises(base.CommandError):
            cmd.execute(context, device='1', new_name='   ')


if __name__ == '__main__':
    unittest.main()

