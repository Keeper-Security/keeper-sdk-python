import unittest
from unittest.mock import MagicMock

from keepersdk.authentication import device_management
from keepersdk.proto import DeviceManagement_pb2


def _device(name: str, last_modified: int = 0) -> DeviceManagement_pb2.Device:
    d = DeviceManagement_pb2.Device()
    d.deviceName = name
    d.lastModifiedTime = last_modified
    d.clientType = DeviceManagement_pb2.COMMANDER
    d.loginState = 0
    d.encryptedDeviceToken = b'\x01\x02'
    return d


class DeviceManagementSdkTests(unittest.TestCase):
    def test_list_user_devices(self):
        auth = MagicMock()
        rs = DeviceManagement_pb2.DeviceUserResponse()
        g = rs.deviceGroups.add()
        g.devices.append(_device('A', 100))
        g.devices.append(_device('B', 200))
        auth.execute_auth_rest.return_value = rs

        devices = device_management.list_user_devices(auth)
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0].name, 'B')
        self.assertEqual(devices[0].list_index, 1)
        self.assertEqual(devices[1].name, 'A')

    def test_logout_user_devices(self):
        auth = MagicMock()
        list_rs = DeviceManagement_pb2.DeviceUserResponse()
        g = list_rs.deviceGroups.add()
        g.devices.append(_device('Laptop', 100))

        action_rs = DeviceManagement_pb2.DeviceActionResponse()
        ar = action_rs.deviceActionResult.add()
        ar.deviceActionStatus = DeviceManagement_pb2.SUCCESS
        ar.encryptedDeviceToken.append(b'\x01\x02')

        auth.execute_auth_rest.side_effect = [list_rs, action_rs]

        names = device_management.logout_user_devices(auth, ['1'])
        self.assertEqual(names, ['Laptop'])
        self.assertEqual(auth.execute_auth_rest.call_count, 2)
        action_call = auth.execute_auth_rest.call_args_list[1]
        self.assertEqual(action_call.kwargs.get('rest_endpoint'), 'dm/device_user_action')
        request = action_call.kwargs.get('request')
        self.assertEqual(
            request.deviceAction[0].deviceActionType,
            DeviceManagement_pb2.DA_LOGOUT,
        )

    def test_remove_user_devices(self):
        auth = MagicMock()
        list_rs = DeviceManagement_pb2.DeviceUserResponse()
        g = list_rs.deviceGroups.add()
        g.devices.append(_device('Phone', 50))

        action_rs = DeviceManagement_pb2.DeviceActionResponse()
        ar = action_rs.deviceActionResult.add()
        ar.deviceActionStatus = DeviceManagement_pb2.SUCCESS
        ar.encryptedDeviceToken.append(b'\x01\x02')

        auth.execute_auth_rest.side_effect = [list_rs, action_rs]

        names = device_management.remove_user_devices(auth, ['1'])
        self.assertEqual(names, ['Phone'])
        request = auth.execute_auth_rest.call_args_list[1].kwargs.get('request')
        self.assertEqual(
            request.deviceAction[0].deviceActionType,
            DeviceManagement_pb2.DA_REMOVE,
        )

    def test_lock_user_devices(self):
        auth = MagicMock()
        list_rs = DeviceManagement_pb2.DeviceUserResponse()
        g = list_rs.deviceGroups.add()
        g.devices.append(_device('Workstation', 75))

        action_rs = DeviceManagement_pb2.DeviceActionResponse()
        ar = action_rs.deviceActionResult.add()
        ar.deviceActionStatus = DeviceManagement_pb2.SUCCESS
        ar.encryptedDeviceToken.append(b'\x01\x02')

        auth.execute_auth_rest.side_effect = [list_rs, action_rs]

        names = device_management.lock_user_devices(auth, ['Workstation'])
        self.assertEqual(names, ['Workstation'])
        request = auth.execute_auth_rest.call_args_list[1].kwargs.get('request')
        self.assertEqual(
            request.deviceAction[0].deviceActionType,
            DeviceManagement_pb2.DA_LOCK,
        )

    def test_account_unlock_user_devices(self):
        auth = MagicMock()
        list_rs = DeviceManagement_pb2.DeviceUserResponse()
        g = list_rs.deviceGroups.add()
        g.devices.append(_device('Tablet', 10))

        action_rs = DeviceManagement_pb2.DeviceActionResponse()
        ar = action_rs.deviceActionResult.add()
        ar.deviceActionStatus = DeviceManagement_pb2.SUCCESS
        ar.encryptedDeviceToken.append(b'\x01\x02')

        auth.execute_auth_rest.side_effect = [list_rs, action_rs]

        names = device_management.account_unlock_user_devices(auth, ['1'])
        self.assertEqual(names, ['Tablet'])
        request = auth.execute_auth_rest.call_args_list[1].kwargs.get('request')
        self.assertEqual(
            request.deviceAction[0].deviceActionType,
            DeviceManagement_pb2.DA_DEVICE_ACCOUNT_UNLOCK,
        )


if __name__ == '__main__':
    unittest.main()
