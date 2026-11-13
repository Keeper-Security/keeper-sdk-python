import unittest
from unittest.mock import MagicMock

from keepersdk.authentication.keeper_auth import AuthContext, KeeperAuth
from keepersdk.proto import router_pb2


class TestRemoteSessionLogout(unittest.TestCase):
    def setUp(self):
        self.auth = KeeperAuth(MagicMock(), AuthContext())
        self.revocations = []
        self.auth.register_session_revoked_callback(self.revocations.append)

    def test_targeted_device_logout_revokes_current_push_session(self):
        self.auth._handle_access_lowered_events({
            "command": "user_access_lowered_events",
            "events": [{
                "eventType": "UALE_DEVICE_LOGOUT",
                "enterpriseUserIds": [12345],
                "deviceId": 98765,
            }],
        })
        self.assertEqual(self.revocations, ['device_logout'])

    def test_logout_all_devices_revokes_current_push_session(self):
        self.auth._handle_access_lowered_events({
            "events": [{
                "eventType": router_pb2.UALE_USER_LOGOUT_ALL_DEVICES,
                "enterpriseUserIds": [12345],
            }],
        })
        self.assertEqual(self.revocations, ['all_devices_logout'])

    def test_unrelated_access_lowered_event_does_not_revoke_session(self):
        self.auth._handle_access_lowered_events({
            "events": [{
                "eventType": "UALE_RECORD_ACCESS_LOST",
                "enterpriseUserIds": [12345],
                "recordUids": ["record-uid"],
            }],
        })
        self.assertEqual(self.revocations, [])

    def test_device_logout_without_device_id_is_ignored(self):
        self.auth._handle_access_lowered_events({
            "events": [{
                "eventType": "UALE_DEVICE_LOGOUT",
                "enterpriseUserIds": [12345],
            }],
        })
        self.assertEqual(self.revocations, [])

    def test_revocation_callback_is_only_invoked_once(self):
        event = {"events": [{"eventType": "UALE_USER_LOGOUT_ALL_DEVICES"}]}
        self.auth._handle_access_lowered_events(event)
        self.auth._handle_access_lowered_events(event)
        self.assertEqual(self.revocations, ['all_devices_logout'])


if __name__ == '__main__':
    unittest.main()
