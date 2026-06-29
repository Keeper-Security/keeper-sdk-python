import unittest
from unittest.mock import MagicMock

from keepersdk.authentication import device_management
from keepersdk.proto import DeviceManagement_pb2


def _device(
    name: str,
    last_modified: int = 0,
    token: bytes = b'\x01\x02',
) -> DeviceManagement_pb2.Device:
    d = DeviceManagement_pb2.Device()
    d.deviceName = name
    d.lastModifiedTime = last_modified
    d.clientType = DeviceManagement_pb2.COMMANDER
    d.loginState = 0
    d.encryptedDeviceToken = token
    return d


def _admin_list_response(enterprise_user_id: int, *devices: DeviceManagement_pb2.Device):
    rs = DeviceManagement_pb2.DeviceAdminResponse()
    user_list = rs.deviceUserList.add()
    user_list.enterpriseUserId = enterprise_user_id
    group = user_list.deviceGroups.add()
    for device in devices:
        group.devices.append(device)
    return rs


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

    def test_logout_user_devices_rejects_duplicate_identifiers(self):
        auth = MagicMock()
        list_rs = DeviceManagement_pb2.DeviceUserResponse()
        g = list_rs.deviceGroups.add()
        g.devices.append(_device('Laptop', 100))
        auth.execute_auth_rest.return_value = list_rs

        with self.assertRaisesRegex(ValueError, 'Duplicate device specified'):
            device_management.logout_user_devices(auth, ['1', '1'])

    def test_logout_user_devices_rejects_id_and_name_for_same_device(self):
        auth = MagicMock()
        list_rs = DeviceManagement_pb2.DeviceUserResponse()
        g = list_rs.deviceGroups.add()
        g.devices.append(_device('Laptop', 100))
        auth.execute_auth_rest.return_value = list_rs

        with self.assertRaisesRegex(ValueError, 'Duplicate device specified'):
            device_management.logout_user_devices(auth, ['1', 'Laptop'])

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

    def test_list_admin_devices(self):
        auth = MagicMock()
        auth.execute_auth_rest.return_value = _admin_list_response(
            12345, _device('A', 100), _device('B', 200)
        )

        devices = device_management.list_admin_devices(auth, [12345])
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0].name, 'B')
        self.assertEqual(devices[0].enterprise_user_id, 12345)
        self.assertEqual(devices[0].list_index, 1)
        call = auth.execute_auth_rest.call_args
        self.assertEqual(call.kwargs.get('rest_endpoint'), 'dm/device_admin_list')

    def test_list_admin_devices_requires_user_ids(self):
        auth = MagicMock()
        with self.assertRaises(ValueError):
            device_management.list_admin_devices(auth, [])

    def test_list_admin_devices_rejects_bool_user_id(self):
        auth = MagicMock()
        with self.assertRaises(ValueError):
            device_management.list_admin_devices(auth, [True])

    def test_logout_admin_user_devices(self):
        auth = MagicMock()
        list_rs = _admin_list_response(12345, _device('Laptop', 100))

        action_rs = DeviceManagement_pb2.DeviceAdminActionResponse()
        ar = action_rs.deviceAdminActionResults.add()
        ar.deviceActionStatus = DeviceManagement_pb2.SUCCESS
        ar.encryptedDeviceToken.append(b'\x01\x02')

        auth.execute_auth_rest.side_effect = [list_rs, action_rs]

        names = device_management.logout_admin_user_devices(auth, 12345, ['1'])
        self.assertEqual(names, ['Laptop'])
        action_call = auth.execute_auth_rest.call_args_list[1]
        self.assertEqual(action_call.kwargs.get('rest_endpoint'), 'dm/device_admin_action')
        request = action_call.kwargs.get('request')
        admin_action = request.deviceAdminAction[0]
        self.assertEqual(admin_action.deviceActionType, DeviceManagement_pb2.DA_LOGOUT)
        self.assertEqual(admin_action.enterpriseUserId, 12345)

    def test_remove_admin_user_devices(self):
        auth = MagicMock()
        list_rs = _admin_list_response(99999, _device('Phone', 50))

        action_rs = DeviceManagement_pb2.DeviceAdminActionResponse()
        ar = action_rs.deviceAdminActionResults.add()
        ar.deviceActionStatus = DeviceManagement_pb2.SUCCESS
        ar.encryptedDeviceToken.append(b'\x01\x02')

        auth.execute_auth_rest.side_effect = [list_rs, action_rs]

        names = device_management.remove_admin_user_devices(auth, 99999, ['Phone'])
        self.assertEqual(names, ['Phone'])
        request = auth.execute_auth_rest.call_args_list[1].kwargs.get('request')
        admin_action = request.deviceAdminAction[0]
        self.assertEqual(admin_action.deviceActionType, DeviceManagement_pb2.DA_REMOVE)
        self.assertEqual(admin_action.enterpriseUserId, 99999)

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

    def test_link_user_devices_requires_two_identifiers(self):
        auth = MagicMock()
        with self.assertRaises(ValueError):
            device_management.link_user_devices(auth, ['1'])

    def test_link_user_devices(self):
        auth = MagicMock()
        list_rs = DeviceManagement_pb2.DeviceUserResponse()
        g = list_rs.deviceGroups.add()
        g.devices.append(_device('Phone', 100, b'\x01'))
        g.devices.append(_device('Laptop', 50, b'\x02'))

        action_rs = DeviceManagement_pb2.DeviceActionResponse()
        ar = action_rs.deviceActionResult.add()
        ar.deviceActionStatus = DeviceManagement_pb2.SUCCESS
        ar.encryptedDeviceToken.extend([b'\x01', b'\x02'])

        auth.execute_auth_rest.side_effect = [list_rs, action_rs]

        names = device_management.link_user_devices(auth, ['1', '2'])
        self.assertEqual(names, ['Phone', 'Laptop'])
        request = auth.execute_auth_rest.call_args_list[1].kwargs.get('request')
        self.assertEqual(
            request.deviceAction[0].deviceActionType,
            DeviceManagement_pb2.DA_LINK,
        )

    def test_unlink_user_devices(self):
        auth = MagicMock()
        list_rs = DeviceManagement_pb2.DeviceUserResponse()
        g = list_rs.deviceGroups.add()
        g.devices.append(_device('Phone', 100, b'\x01'))
        g.devices.append(_device('Laptop', 50, b'\x02'))

        action_rs = DeviceManagement_pb2.DeviceActionResponse()
        ar = action_rs.deviceActionResult.add()
        ar.deviceActionStatus = DeviceManagement_pb2.SUCCESS
        ar.encryptedDeviceToken.extend([b'\x01', b'\x02'])

        auth.execute_auth_rest.side_effect = [list_rs, action_rs]

        names = device_management.unlink_user_devices(auth, ['Phone', 'Laptop'])
        self.assertEqual(names, ['Phone', 'Laptop'])
        request = auth.execute_auth_rest.call_args_list[1].kwargs.get('request')
        self.assertEqual(
            request.deviceAction[0].deviceActionType,
            DeviceManagement_pb2.DA_UNLINK,
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


    def test_resolve_device_requires_exact_name(self):
        auth = MagicMock()
        list_rs = DeviceManagement_pb2.DeviceUserResponse()
        g = list_rs.deviceGroups.add()
        g.devices.append(_device('Web Vault Chrome', 100))
        g.devices.append(_device('Commander CLI on macOS', 50))
        auth.execute_auth_rest.return_value = list_rs

        with self.assertRaises(ValueError):
            device_management.logout_user_devices(auth, ['Web Vault'])

    def test_resolve_device_exact_name(self):
        auth = MagicMock()
        list_rs = DeviceManagement_pb2.DeviceUserResponse()
        g = list_rs.deviceGroups.add()
        g.devices.append(_device('Web Vault Chrome', 100))

        action_rs = DeviceManagement_pb2.DeviceActionResponse()
        ar = action_rs.deviceActionResult.add()
        ar.deviceActionStatus = DeviceManagement_pb2.SUCCESS
        ar.encryptedDeviceToken.append(b'\x01\x02')

        auth.execute_auth_rest.side_effect = [list_rs, action_rs]

        names = device_management.logout_user_devices(auth, ['Web Vault Chrome'])
        self.assertEqual(names, ['Web Vault Chrome'])

    def test_ambiguous_device_name_lists_matches(self):
        auth = MagicMock()
        list_rs = DeviceManagement_pb2.DeviceUserResponse()
        g = list_rs.deviceGroups.add()
        g.devices.append(_device('web Vault Chrome', 200, b'\x01'))
        g.devices.append(_device('Web Vault Chrome', 100, b'\x02'))
        auth.execute_auth_rest.return_value = list_rs

        with self.assertRaisesRegex(ValueError, 'No matching devices found'):
            device_management.unlock_user_devices(auth, ['Web Vault Chrome'])


if __name__ == '__main__':
    unittest.main()
