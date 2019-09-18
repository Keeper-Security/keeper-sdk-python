from unittest import TestCase

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from keepersdk import crypto, utils


class TestCrypto(TestCase):
    def test_key_derive_v1(self):
        password = 'q2rXmNBFeLwAEX55hVVTfg'
        salt = utils.base64_url_decode('Ozv5_XSBgw-XSrDosp8Y1A')
        iterations = 1000
        expected_key = utils.base64_url_decode('nu911pKhOIeX_lToXa4uIUuMPg1pj_3ZGpGmd7OjvRs')
        key_hash = crypto.derive_keyhash_v1(password, salt, iterations)
        self.assertEqual(key_hash, expected_key)

    def test_key_derive_v2(self):
        password = 'q2rXmNBFeLwAEX55hVVTfg'
        salt = utils.base64_url_decode('Ozv5_XSBgw-XSrDosp8Y1A')
        iterations = 1000
        expected_key = utils.base64_url_decode('rXE9OHv_gcvUHdWuBIkyLsRDXT1oddQCzf6PrIECl2g')
        domain = '1oZZl0fKjU4'
        key_hash = crypto.derive_keyhash_v2(domain, password, salt, iterations)
        self.assertEqual(key_hash, expected_key)

    def test_load_private_key(self):
        private_key = 'MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCpHQCOYFejfvWlia9LU0z' \
                      'ydeVsC_mpRs9i5XopXAqM3dPxZfkrocMaXf7KUBsjTa8jMq576ANuOjXBQanaqEA1zVXGWU' \
                      'tJaeQmbBu4ZRMRangA2O6ygyE-8TCdrVc92WtIx2wqiSNs_3FuC4929fHmgFqoCuusYSD7f' \
                      'pWLuaID-D9RPgMpyvKCUPhfHQf23kdq_5-vPapwSzKH0ULR83Kif-694R0_Zpz6RrHy87kR' \
                      '5V8HM53D5Y9oG1Q7WHutJnrEo6brHU5qE1NQXLsKCbTfwm4zAcKFMrb0f0Q6Wps467NgDUQ' \
                      '3MvzyEQul76SXhGak1L3gEkOyyKQUVuOiIBV_AgMBAAECggEAEH0pbrhqEyDv5qIUG24V1J' \
                      'Y2NmC8iQrEccoaLSoyRSXj4mek8eIl2c5MZ4GEA98xMmdgp-gpXXgDgcJbQ1ygVh6dPGe8d' \
                      'X4DptNnqIUCZPJSnRKJw5IRjceKi_U4ymkGkuQO4d7ZO2l0r9wkst6sJWNic3wNGpOl2Z-w' \
                      'CR2idGx5fKFGHA7rIXBXL1MRz384W6oYw6zLn9Ui2zqkbSxoklRCU64tPEfC092WiqMjyXf' \
                      'IyIN9e8kXb96lv89ikqQBBnL9RYzm7g_-mdtR0ibJijocGaer6o7TsntvfI5IDNaGSUEPtw' \
                      'yHW5xI7IX367TeYs5_Hb5Jeri0i5QvPdEdkQKBgQDRGP6KkIoQ_BA5FWIMVhiTW3HMVJUpV' \
                      'f1D6jOXqL3eRNfHwYXu-RcvpJoRsoMDYQBG5zOvWCPKaW-BEDBuxftsPKVIXoSyY9n4Rxw1' \
                      '7gaheZ9uAwUOoaveNVSbARjCS17oS8_YdrYYPAi5cWFxdbGBttDEYYRxLmeJ6LWZXSO_6wK' \
                      'BgQDPC_0EhiR4ELr-R6MPZXA3MLUmX3u-DYi3ZRFNlQY8W9xeHUR3-LWK1fAnvAGPIF3Ask' \
                      'whaNlwBgoRP010GmzaWgBNs4evDjMUSqMqv9f7FJVThu6eKmhjjR-GXprXmeBRnj3c4l79i' \
                      '1cQEdNUeiuW0hi66C7TMqTq4ptT9u3vvQKBgBHz_m7xSBl7Ov1bu6ZpggSs9lFf9cqtymgZ' \
                      'ZMKhx2OdL5XEJPbGxlnd3Sil1h_lJTvxP_vPKouHj_5Z4H6yWwsJDfvvuZ8DecSafm6W-FT' \
                      'G94xfkACYmwQiOhhw-Ko-BHEXiUoBr1LXXLxnYsF2JH6JrtUdtlxtapBpvaXkXFxvAoGALP' \
                      '86_te0Z0-jhA3Hl1oBWE1CoVNRDk3cr5bMeuLvVwDT1LRho_0uXzz9k3UdlaCAH5fgScaCs' \
                      'wDtATCTwa7Yh1_V_w0MaPQaD8fkzC6jXtLrXRrPExq-UxxhhI9c8YxknvhYE4AzCsFUq45k' \
                      'MlDW1lFUxJIfUxEHnHChN09MCLUCgYBeolR8MCO0tHTAWguVXQZYY45sqQ9kUJsV2_T8JjZ' \
                      '2TScqdKxhEKiCIU-31eFkbmRrAS11-qI0EPJ41Uu7oVpmdGSJ3-1Sowp8JguM0OrfU4PU_C' \
                      '_K6HoezU-Evb6e3q31vskzLMqNar84-5M8fRASsveiIVtNpnh8NemUf_pKfA'
        crypto.load_private_key(utils.base64_url_decode(private_key))


    def test_aesgcm_encryption(self):
        key = utils.base64_url_decode('c-EeCGlAO7F9QoJThlFBrhSCLYMe1H6GtKP-rezDnik')
        nonce = utils.base64_url_decode('Nt9_Y37C_43eRCRQ')
        data = utils.base64_url_decode("nm-8mRG7xYwUG2duaOZzw-ttuqfetWjVIzoridJF0EJOGlDLs1ZWQ7F9mOJ0Hxuy" +
                                        "dFyojxdxVo1fGwbfwf0Jew07HhGGE5UZ_s57rQvhizDW3F3z9a7EqHRon0EilCbMhIzE")
        expected_data = utils.base64_url_decode("Nt9_Y37C_43eRCRQCptb64zFaJVLcXF1udabOr_fyGXkpjpYeCAI7zVQD4JjewB" +
                                                "CP1Xp7D6dx-pxdRWkhDEnVhJ3fzezi8atmmzvf2ICfkDK0IHHB8iNSx_R1Ru8To" +
                                                "zb-IdavT3wKi7nKSJLDdt-dk-Mw7bCewpZtg4wY-1UQw")
        enc_data = crypto.encrypt_aes_v2(data, key, nonce)
        self.assertEqual(enc_data, expected_data)

        unenc_data = crypto.decrypt_aes_v2(expected_data, key)
        self.assertEqual(unenc_data, data)

    def test_local_rsa(self):
        public_key = serialization.load_pem_public_key(_PUBLIC_KEY.encode('utf-8'), default_backend())
        private_key = serialization.load_pem_private_key(_PRIVATE_KEY.encode('utf-8'), _PRIVATE_KEY_PASSWORD.encode('utf-8'), default_backend())
        data = os.urandom(100)
        enc_data = crypto.encrypt_rsa(data, public_key)
        dec_data = crypto.decrypt_rsa(enc_data, private_key)
        self.assertEqual(data, dec_data)

    def test_other_rsa(self):
        private_key = serialization.load_pem_private_key(_PRIVATE_KEY.encode('utf-8'), _PRIVATE_KEY_PASSWORD.encode('utf-8'), default_backend())
        data = utils.base64_url_decode('fDxt4nJLZPrRSMozaD1Vkt1QNS5bdAoEGmXv1mbE3DWo5HWJ13RBPuRQr7gqiZ542BLN_R8n8lmJrZ5RIVnvgB93y7SSuD9BxpP55RZ6twAl0vXBeVpPn9CTAgTHy8kM_U4h_g')
        dotnet_encrypted = utils.base64_url_decode("""XUcJfak5bGW9UyqjkF8CAfT196VYMEFTu-HsZdWgkgDy9faufL3TLiX5B9pAAl8
Ms3W4ZHGhVx7pdU_7lFTP7VYCr-ODwhbh4Qjp7tAxdlhh5GbXM-IuvcG1Fx1ZEx
UPp9VdB7jlKF7--gdxXuezqktQxs8X2JRFVUBsJho8zBXLfdzILPjdoSiq_3R9S
Jp_KhVOJfT1CB6iUap2BOqUfXkISbO57RUJ7-0IthcrNVSx2nqlNSGFSfAMzTYK
_kAEmAf7HJ_Zl0ff3e_9qSEu_l1iNpnySPAersLd6_jjnqJWcI5I6oO9MmEGsoa
NCr6rWBxMmpjLcB3siaDCNT9laQ""")
        dec_data = crypto.decrypt_rsa(dotnet_encrypted, private_key)
        self.assertEqual(data, dec_data)


_PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,7359ABCB9854B5CB781E4910662C5EF1

u1i/Mj22bT6AegV38qTsz0mK/QFbGpveS9dq4GXkYVA5JjqowcVsl1HUq2mIhDmW
wYRhkqGWD6IJkt++mDIpv74VKYYuzxTVvt4V46LS/mXn9xqO8g8Cy1qxWznRBPZe
a6/qziQpSI1R4PltIcD1gQHPIJiHINOi4Zi1GT6FTRzZwQ+08rOFfRchvP/rG8hX
KgLywsk9p44exMNJBJhOVTs6UeC4zGdMxNN++Qa+3o+6G8FVgyR4KNGqcFVoYGe6
L5K5KoJz4LwhUy3NDL9TSftxqvXsbiFtUw4BSEYjdyDYQz/ytpFkyGJIzn7vutx+
XbEIMRi6RR2qObI9TdiA5w7sOthvCiGbpzqlH6b++pIRNYiUPe+Ec8SeEbkM8wZB
IFx6xCpDKZQPyCnHngwYIw/iCXqO5UyJjDCnDHOVpMi/BbMJsKp7U+qcrUmN9gUr
VMFRlUZpps5Im3wu3gebZ6Fu41JYK2LqcgEOnh0EbeeZIvH3+uv/QIHdJPYSbsMU
Ns2KJQc+n4PsZa7kZf/CGAq926Y302o9SV2pX1GAcwoHJWkfukZhpt3ikJSrnHVD
FAIZbA0xt4XdbDMVg5T6Er+q1IO1zrZeQ/NLsRR+/JLz3+DvtIKrVMTLtGbl/VV4
rROt9l6YnF2F8CMaMz68v+19vzo1zEob/WD/8Ye3YQq66meJ/+NjwyTmMrZxsO/l
FHeDgDs1r2Nc1uC2/n1UiiZyFTaBzkj/5QUnpBm33V/P63+pN6cw0qEvjNEwdIOC
d5Ohky1d1ayhSeVHkx1ZYcSTriicgWcWTOV+zckJ+VAqvSCZV4A+NMqZGVzPhMgC
h9GWvIXfMDhXIDzBsQz2W3zseJFSzL4av8b/AxTDapOeS9M8FzsbEDJC7YfiLVWK
6bFOLr2dg5Lm41iyWmp7NK2+IUFN15DgMIbHcpfD24F+cs73hjE3E56rsb8dBifG
Q1izqwFiopK+1z9C/EWBmmY3AcyqjXEQl3DWnL2IbYnhmm/SN040BGVZKJcUBUlk
b7RPQF+uZWlM8EWLTqCZQUfl3bogxOcFryyElBPDVRq4Z/x4di2FuUbmI/Mbs1g7
PiBWKIC8CHk3sLezXgMn1thkKsRI3xN+jZcGTZ6lhTVKUAbbW8mqRzBtyjPHbjUC
9PRSeJRDc10ZYnyWhLXa2lSgY12obXNuxLi8eKg6VuBnVzh4CvjOmJY3NlA5xsUi
YLl49YLLQqBU2IwrgqYm+7n2D8PmnhwPUPj2shNoIi9gtAhx8n0pyypgzd8iTtQZ
3IxO1zaNjJOal4er299DcoBsZ5cZ7EU6ltwtUCNqGyaVWwSqjAKtiPGpjT/eEAeL
KLzX+F5r+dUUsy5m8ds+6TUWDxLaqT8PcugnUxT8f3JokODv7JHSiogB1ETeczKS
RJfJH63edAQLxl+rayIqsTuUntmMNgE3olQWexCChX9b8xW6OzVgw8jU6WX0OGOB
5qkDxT9de8CpseIymuDX8AYIpPxIHJdigTBBfYp34hPAKuBpAwDPNS1FiOZYYZSB
84VHEOeXkUpBgAGQwphDZITltMDnssSGPbCX9EHM5+mNVkmQw+SDJbcgXm0jNVtC
-----END RSA PRIVATE KEY-----
'''
_PRIVATE_KEY_PASSWORD = 'E,{-qhsm;<cq]3D(3H5K/'
_PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0AjmBXo371pYmvS1NM
8nXlbAv5qUbPYuV6KVwKjN3T8WX5K6HDGl3+ylAbI02vIzKue+gDbjo1wUGp2qhA
Nc1VxllLSWnkJmwbuGUTEWp4ANjusoMhPvEwna1XPdlrSMdsKokjbP9xbguPdvXx
5oBaqArrrGEg+36Vi7miA/g/UT4DKcryglD4Xx0H9t5Hav+frz2qcEsyh9FC0fNy
on/uveEdP2ac+kax8vO5EeVfBzOdw+WPaBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm0
38JuMwHChTK29H9EOlqbOOuzYA1ENzL88hELpe+kl4RmpNS94BJDssikFFbjoiAV
fwIDAQAB
-----END PUBLIC KEY-----
'''