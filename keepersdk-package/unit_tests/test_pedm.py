from unittest import TestCase

import requests

from keepersdk import crypto, utils
from keepersdk.plugins.pedm import pedm_shared
from keepersdk.proto import pedm_pb2, APIRequest_pb2

class TestPedm(TestCase):
    def test_collection_uid(self):
        encoded_hash_key = '3MtZj3S32gPKNaJCNLAUmzJ9W5lESN-7Uo9A505HDj4'
        hash_key = utils.base64_url_decode(encoded_hash_key)
        resource_uid = pedm_shared.get_collection_uid(hash_key, 5, '%system%/ftp')
        self.assertEqual(resource_uid, 'jH_Vwhf6vFaeVk_NxGjNaQ')

    def test_support(self):
        encoded_key = 'WgcyilvaGmRxYk2uHI2EAPmFL9NoD0VXOCy6tTiwbUA'
        encryption_key = utils.base64_url_decode(encoded_key)
        rq = pedm_pb2.GetActiveAgentCountRequest()
        rq.enterpriseUid.append(191)

        encrypted_payload = crypto.encrypt_aes_v2(rq.SerializeToString(), encryption_key)
        envelope = APIRequest_pb2.ApiRequestByKey()
        envelope.keyId = 2
        envelope.payload = encrypted_payload
        envelope.username = 'sergey+a2@callpod.com'

        url = 'https://connect.dev.keepersecurity.com/api/bi/active_agent_count'
        response = requests.post(url, data=envelope.SerializeToString())

        rs = APIRequest_pb2.ApiRequestByKey()
        rs.ParseFromString(response.content)

        self.assertEqual(rs.keyId, 2)
        decrypted_bytes = crypto.decrypt_aes_v2(rs.payload, encryption_key)
        counts = pedm_pb2.GetActiveAgentCountResponse()
        counts.ParseFromString(decrypted_bytes)
        self.assertEqual(len(counts.agentCount), 1)
        count = counts.agentCount[0]
        self.assertEqual(count.activeAgents, 12)


