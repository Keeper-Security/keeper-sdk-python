import io
from unittest import TestCase

from keepersdk import crypto, utils

from cryptography.hazmat.primitives import serialization

class TestCrypto(TestCase):
    def test_key(self):
        rr = utils.base64_url_encode(crypto.get_random_bytes(32))
        pass

    def test_rsa_invalid_key(self):
        encrypted_text = "NePhr5g-Ee8oyYrPZUlsYanKmVKC1GTCFk-t0JoHm_ceQlZjBMd-_qZb-73_n-hSyJtkzQUa6jmoPLNlkVkukiiKMOFD93V4N4_1yxjyLMHp2RMHZJjszJwiqZ0JAjySpFOSJ5owYUrSVyhIgl6d3a_l_dbTxRNqy2UYMkMeSSJv2LjufxUyf5eYpPloWWWx8WSqizXuCo3hDfe0RtIRNshKAx1I1Xc6pixib58lIRtD0NzO6jsGyyGbdlqI6W0olkSvZpBVU5edqmAhclXLoeNF5xK7jYuGxqBFxrhKCwRcbaSOI-1DdyTYdj5LC_MmB5QXi-Lc_RoGs0g5sTIP"
        private_key_text = "MIIEogIBAAKCAQBc7ja0E2D3FqTgrCMl-W_wjyH8FfFOlfiIbUC5U2iW_8zeo6KyHI-O47XF7uniILOQmj7q02qR8jPdWwYzGRfQyASDbk41nWUrEGr-RQ6bht_jRJNOYiwIza5kr06mcgoXjsRBzNhhMsTl-aTZaBRUGVBx0mLdic70E_0W9dKyHJvbBfSPxJto7hCuu93yViIN2w_QSNrOzagFFZGhdz-BzrOybuUhoBE18cARTdPUZ_UlU_vIymORTHbBvneqXZ2Ua6ohsc7_AM38FYlftkJBNDGnH_UruLGd6kLzGszzdchxexjjE488rahibXDvMbl3-hR1OyL2-6q_uPi5whhpAgMBAAECggEAORHVqFrqRnOyh4NPBogbtXjBHyV-jotNGMM3Z1iQt4KaFvQY-xbNFqxCui5RlZwNijUfhGiXXs-GCF9Y_FJhrMbY9rnr78McGQk5G7PfF6YJonE_oXhqoHFnss9yFoecKQF1Bw-8plxeTPk1wonHSipNm8jfDDwQSxZnbA1E-joW4Gy9MchmE96pS2OxrN8y2MpEhKMz_fkCbUjUj5-ipP8hYJr-WbpcnyeWDgFS3j7xuB31312yroWEgaQ_a8hbVM6gyqn2DuLjcYImCR38ZK39vBtqc9j9E_7Cl_BSfGR7FFmoIVndW60XQFEJJgxAZhbusYjAb59H6UfDRz4tjQKBgQCsdEvXrUP3Rx_7juvVEt6k8MbdDBuERvDlz-1KMEXa_3e5TZStgU1-MNcF98Kx9lHqHd7TZuCmsFf4wnvVZLhO9AH6uR7VvOCXtnqfbiZG54YpQzYty4o_EqM-TosPaRaF6-z6YnBtSUS74qUDzKa3RKbpO66zstM3CfsPsJzLFwKBgQCJ82p4_1g4Oh-ro0HNWH42u3XNN83YynPmSkeYCTaEhMVfVx4EOh7LuPV4itt7U9SkcWkFhGw1abwZC4m9cEHzsVOFR5Hk5Gnke7MGHRHTjat_olYcb5wYE1p3KcZOa6Zoa4J52UliehbE6e3HpcF8P3PiJ_16QvUn3hIl7UhofwKBgQCJTHnJd6_h4mWLMSl_VWufI_cfq_EIajaGsPk5lJ85ESVviV2ymXxp2FaI8M24Q-TJoQhzhLec3k7bxXMz3OGEMm6U_-eVwa-J-gU8g0TENLYyiclLwn4JYzxGcd_y3_bHnqLoYZEi4S9w6qv4D2o4BNdiX1rixJ-2dSLGRhU-9wKBgFENbh-Nl93heL41-_GU7wNlfT-IbC_WM-a4-fvAXgHaqMTtwLsnEvULxV5_55k8lhHQeK4_MfzoFRZ6CwH9NSLjq3kBphzgf785VuRerByqfntNfF7UzNfwdxTQvK1S3sE3eb_yBQYRSdOExqqpH1fLSGE2sd3l_XjhJ7SVCBgtAoGAGhV87Flduuxm29U28EWIBAZGJnABgZocEdc6xTj_3fdEW1CSZXLL5fR27OPeO_esDhZKgFsNrHw8bdNFXtiWLNECwPleLhEYnmQHbd40hZ6mAQu899i_OVIyzgXtkqS1-nD3uLTl8VRxxOmi3NhnaQrr6Kl2Ou6kVYyvfO8AoVg"
        encrypted_bytes = utils.base64_url_decode(encrypted_text)
        private_key = crypto.load_rsa_private_key(utils.base64_url_decode(private_key_text))
        _ = crypto.decrypt_rsa(encrypted_bytes, private_key)

    def test_encrypt_transform(self):
        key = utils.generate_aes_key()
        data = bytearray(999)
        for i in range(len(data)):
            data[i] = i & 0xff

        transform_v2 = crypto.StreamCrypter()
        transform_v2.key = key
        transform_v2.is_gcm = True
        stream = io.BytesIO(data)
        with transform_v2.set_stream(stream, for_encrypt=True) as enc_stream:
            enc_data = enc_stream.read()
        self.assertEqual(len(enc_data), len(data) + 12 + 16)
        stream = io.BytesIO(enc_data)
        with transform_v2.set_stream(stream, for_encrypt=False) as dec_stream:
            dec_data = dec_stream.read()
        self.assertEqual(data, dec_data)

    def test_decrypt_aes_v1(self):
        data = utils.base64_url_decode('KvsOJmE4JNK1HwKSpkBeR5R9YDms86uOb3wjNvc4LbUnZhKQtDxWifgA99tH2ZuP')
        key = utils.base64_url_decode('pAZmcxEoV2chXsFQ6bzn7Lop8yO4F8ERIuS7XpFtr7Y')
        data = crypto.decrypt_aes_v1(data, key)
        self.assertEqual(data, utils.base64_url_decode('6lf4FGVyhDRnRhJ91TrahjIW8lTqGA'))

    def test_encrypt_aes_v2(self):
        key = utils.base64_url_decode('c-EeCGlAO7F9QoJThlFBrhSCLYMe1H6GtKP-rezDnik')
        data = utils.base64_url_decode('nm-8mRG7xYwUG2duaOZzw-ttuqfetWjVIzoridJF0EJOGlDLs1ZWQ7F9mOJ0Hxuy' +
                                       'dFyojxdxVo1fGwbfwf0Jew07HhGGE5UZ_s57rQvhizDW3F3z9a7EqHRon0EilCbMhIzE')
        nonce = utils.base64_url_decode('Nt9_Y37C_43eRCRQ')
        enc_data = crypto.encrypt_aes_v2(data, key, nonce)
        expected_data = utils.base64_url_decode('Nt9_Y37C_43eRCRQCptb64zFaJVLcXF1udabOr_fyGXkpjpYeCAI7zVQD4JjewB' +
                                                'CP1Xp7D6dx-pxdRWkhDEnVhJ3fzezi8atmmzvf2ICfkDK0IHHB8iNSx_R1Ru8Tozb-IdavT3wKi7nKSJLDdt-dk-Mw7bCewpZtg4wY-1UQw')
        self.assertEqual(enc_data, expected_data)

        dec_data = crypto.decrypt_aes_v2(enc_data, key)
        self.assertEqual(dec_data, data)

    def test_encrypt_aes_v1(self):
        iv = utils.base64_url_decode('KvsOJmE4JNK1HwKSpkBeRw')
        block = utils.base64_url_decode('6lf4FGVyhDRnRhJ91TrahjIW8lTqGA')
        key = utils.base64_url_decode('pAZmcxEoV2chXsFQ6bzn7Lop8yO4F8ERIuS7XpFtr7Y')
        enc = crypto.encrypt_aes_v1(block, key, iv)
        encoded = utils.base64_url_encode(enc)
        self.assertEqual(encoded, 'KvsOJmE4JNK1HwKSpkBeR5R9YDms86uOb3wjNvc4LbUnZhKQtDxWifgA99tH2ZuP')

    def test_encrypt_rsa(self):
        data = crypto.get_random_bytes(100)
        puk = crypto.load_rsa_public_key(utils.base64_url_decode(_test_public_key))
        enc_data = crypto.encrypt_rsa(data, puk)
        prk = crypto.load_rsa_private_key(utils.base64_url_decode(_test_private_key))
        dec_data = crypto.decrypt_rsa(enc_data, prk)
        self.assertEqual(data, dec_data)

    def test_derive_key_hash_v1(self):
        password = 'q2rXmNBFeLwAEX55hVVTfg'
        salt = utils.base64_url_decode('Ozv5_XSBgw-XSrDosp8Y1A')
        iterations = 1000
        expected_key = utils.base64_url_decode('nu911pKhOIeX_lToXa4uIUuMPg1pj_3ZGpGmd7OjvRs')
        key_hash = crypto.derive_keyhash_v1(password, salt, iterations)
        self.assertEqual(key_hash, expected_key)

    def test_derive_key_hash_v2(self):
        password = 'q2rXmNBFeLwAEX55hVVTfg'
        salt = utils.base64_url_decode('Ozv5_XSBgw-XSrDosp8Y1A')
        iterations = 1000
        expected_key = utils.base64_url_decode('rXE9OHv_gcvUHdWuBIkyLsRDXT1oddQCzf6PrIECl2g')
        domain = '1oZZl0fKjU4'
        key_hash = crypto.derive_keyhash_v2(domain, password, salt, iterations)
        self.assertEqual(key_hash, expected_key)

    def test_ecdh_shared_key(self):
        priv_key = "HIIeyuuRkVGvhtax8mlX7fangaC6DKa2R8VAg5AAtBY"
        pub_key = "BBbdHwhMWW6gTtUU1Qy6ICgFOMOMTJK5agJhPSWcsXBzh3WNprrZMTDzDcLmj3yfmJFVVeEdiccdPdBe1C1r6Ng"
        private_key = crypto.load_ec_private_key(utils.base64_url_decode(priv_key))
        public_key = crypto.load_ec_public_key(utils.base64_url_decode(pub_key))
        encryption_key = crypto.ec_shared_key(public_key, private_key)
        encoded_key = utils.base64_url_encode(encryption_key)
        self.assertEqual(encoded_key, "liPcydc_ZsUiIFB1k4KCMTeqr_8N3SKulHpRk_TdGoE")


_test_public_key = "MIIBCgKCAQEAqR0AjmBXo371pYmvS1NM8nXlbAv5qUbPYuV6KVwKjN3T8WX5K6HD" \
                   "Gl3-ylAbI02vIzKue-gDbjo1wUGp2qhANc1VxllLSWnkJmwbuGUTEWp4ANjusoMh" \
                   "PvEwna1XPdlrSMdsKokjbP9xbguPdvXx5oBaqArrrGEg-36Vi7miA_g_UT4DKcry" \
                   "glD4Xx0H9t5Hav-frz2qcEsyh9FC0fNyon_uveEdP2ac-kax8vO5EeVfBzOdw-WP" \
                   "aBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm038JuMwHChTK29H9EOlqbOOuzYA1ENzL8" \
                   "8hELpe-kl4RmpNS94BJDssikFFbjoiAVfwIDAQAB"

_test_private_key = "MIIEogIBAAKCAQEAqR0AjmBXo371pYmvS1NM8nXlbAv5qUbPYuV6KVwKjN3T8WX5" \
                    "K6HDGl3-ylAbI02vIzKue-gDbjo1wUGp2qhANc1VxllLSWnkJmwbuGUTEWp4ANju" \
                    "soMhPvEwna1XPdlrSMdsKokjbP9xbguPdvXx5oBaqArrrGEg-36Vi7miA_g_UT4D" \
                    "KcryglD4Xx0H9t5Hav-frz2qcEsyh9FC0fNyon_uveEdP2ac-kax8vO5EeVfBzOd" \
                    "w-WPaBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm038JuMwHChTK29H9EOlqbOOuzYA1E" \
                    "NzL88hELpe-kl4RmpNS94BJDssikFFbjoiAVfwIDAQABAoIBABB9KW64ahMg7-ai" \
                    "FBtuFdSWNjZgvIkKxHHKGi0qMkUl4-JnpPHiJdnOTGeBhAPfMTJnYKfoKV14A4HC" \
                    "W0NcoFYenTxnvHV-A6bTZ6iFAmTyUp0SicOSEY3Hiov1OMppBpLkDuHe2TtpdK_c" \
                    "JLLerCVjYnN8DRqTpdmfsAkdonRseXyhRhwO6yFwVy9TEc9_OFuqGMOsy5_VIts6" \
                    "pG0saJJUQlOuLTxHwtPdloqjI8l3yMiDfXvJF2_epb_PYpKkAQZy_UWM5u4P_pnb" \
                    "UdImyYo6HBmnq-qO07J7b3yOSAzWhklBD7cMh1ucSOyF9-u03mLOfx2-SXq4tIuU" \
                    "Lz3RHZECgYEA0Rj-ipCKEPwQORViDFYYk1txzFSVKVX9Q-ozl6i93kTXx8GF7vkX" \
                    "L6SaEbKDA2EARuczr1gjymlvgRAwbsX7bDylSF6EsmPZ-EccNe4GoXmfbgMFDqGr" \
                    "3jVUmwEYwkte6EvP2Ha2GDwIuXFhcXWxgbbQxGGEcS5niei1mV0jv-sCgYEAzwv9" \
                    "BIYkeBC6_kejD2VwNzC1Jl97vg2It2URTZUGPFvcXh1Ed_i1itXwJ7wBjyBdwLJM" \
                    "IWjZcAYKET9NdBps2loATbOHrw4zFEqjKr_X-xSVU4bunipoY40fhl6a15ngUZ49" \
                    "3OJe_YtXEBHTVHorltIYuugu0zKk6uKbU_bt770CgYAR8_5u8UgZezr9W7umaYIE" \
                    "rPZRX_XKrcpoGWTCocdjnS-VxCT2xsZZ3d0opdYf5SU78T_7zyqLh4_-WeB-slsL" \
                    "CQ3777mfA3nEmn5ulvhUxveMX5AAmJsEIjoYcPiqPgRxF4lKAa9S11y8Z2LBdiR-" \
                    "ia7VHbZcbWqQab2l5FxcbwKBgCz_Ov7XtGdPo4QNx5daAVhNQqFTUQ5N3K-WzHri" \
                    "71cA09S0YaP9Ll88_ZN1HZWggB-X4EnGgrMA7QEwk8Gu2Idf1f8NDGj0Gg_H5Mwu" \
                    "o17S610azxMavlMcYYSPXPGMZJ74WBOAMwrBVKuOZDJQ1tZRVMSSH1MRB5xwoTdP" \
                    "TAi1AoGAXqJUfDAjtLR0wFoLlV0GWGOObKkPZFCbFdv0_CY2dk0nKnSsYRCogiFP" \
                    "t9XhZG5kawEtdfqiNBDyeNVLu6FaZnRkid_tUqMKfCYLjNDq31OD1Pwvyuh6Hs1P" \
                    "hL2-nt6t9b7JMyzKjWq_OPuTPH0QErL3oiFbTaZ4fDXplH_6Snw"
