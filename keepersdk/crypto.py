#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2019 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import abc
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA512
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key

_CRYPTO_BACKEND = default_backend()


def pad_data(data):    # type: (bytes) -> bytes
    padder = PKCS7(16*8).padder()
    return padder.update(data) + padder.finalize()


def unpad_data(data):     # type: (bytes) -> bytes
    unpadder = PKCS7(16*8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def get_random_bytes(length):
    return os.urandom(length)


def load_private_key(der_private_key, password=None):
    return load_der_private_key(der_private_key, password, _CRYPTO_BACKEND)


def load_public_key(der_public_key):
    return load_der_public_key(der_public_key, _CRYPTO_BACKEND)


def encrypt_aes_v1(data, key, iv=None, use_padding=True):
    iv = iv or os.urandom(16)
    cipher = Cipher(AES(key), CBC(iv), backend=_CRYPTO_BACKEND)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(pad_data(data) if use_padding else data) + encryptor.finalize()
    return iv + encrypted_data


def decrypt_aes_v1(data, key, use_padding=True):
    iv = data[:16]
    cipher = Cipher(AES(key), CBC(iv), backend=_CRYPTO_BACKEND)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data[16:]) + decryptor.finalize()
    return unpad_data(decrypted_data) if use_padding else decrypted_data


def encrypt_aes_v2(data, key, nonce=None):
    aesgcm = AESGCM(key)
    nonce = nonce or os.urandom(12)
    enc = aesgcm.encrypt(nonce, data, None)
    return nonce + enc


def decrypt_aes_v2(data, key):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(data[:12], data[12:], None)


def encrypt_rsa(data, rsa_key):
    return rsa_key.encrypt(data, PKCS1v15())


def decrypt_rsa(data, rsa_key):
    return rsa_key.decrypt(data, PKCS1v15())


def derive_key_v1(password, salt, iterations):
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=iterations, backend=_CRYPTO_BACKEND)
    return kdf.derive(password.encode('utf-8'))


def derive_keyhash_v1(password, salt, iterations):
    derived_key = derive_key_v1(password, salt, iterations)
    hf = Hash(SHA256(), backend=_CRYPTO_BACKEND)
    hf.update(derived_key)
    return hf.finalize()


def derive_keyhash_v2(domain, password, salt, iterations):
    kdf = PBKDF2HMAC(algorithm=SHA512(), length=64, salt=salt, iterations=iterations, backend=_CRYPTO_BACKEND)
    derived_key = kdf.derive((domain+password).encode('utf-8'))
    hf = HMAC(derived_key, SHA256(), backend=_CRYPTO_BACKEND)
    hf.update(domain.encode('utf-8'))
    return hf.finalize()


class AesStreamCryptor(abc.ABC):
    def __init__(self, is_encrypt, block_size):     # type: (bool, int) -> None
        self.is_encrypt = is_encrypt
        self.block_size = block_size
        self.input_tail = None            # type: bytes or None
        self.output_tail = None           # type: bytes or None

    def update(self, in_data):
        if self.input_tail:
            in_data = self.input_tail + in_data
            self.input_tail = None
        tail = len(in_data) % self.block_size
        if tail != 0:
            self.input_tail = in_data[-tail:]
            in_data = in_data[:-tail]
        if len(in_data) == 0:
            return b''

        out_data = self.native_update(in_data)
        if self.is_encrypt:
            return out_data
        else:
            if self.output_tail:
                out_data = self.output_tail + out_data
                self.output_tail = None
            if len(out_data) > self.block_size:
                self.output_tail = out_data[-self.block_size:]
                return out_data[:-self.block_size]
            else:
                self.output_tail = out_data
                return b''

    def finish(self):
        if self.is_encrypt:
            out_data = self.native_update(pad_data(self.input_tail or b''))
            if len(out_data) > 0:
                if self.output_tail:
                    self.output_tail = self.output_tail + out_data
                else:
                    self.output_tail = out_data

        out_data = self.native_finish()

        if self.output_tail:
            out_data = self.output_tail + out_data
            self.output_tail = None

        if self.is_encrypt:
            return out_data
        else:
            return unpad_data(out_data)

    @abc.abstractmethod
    def native_update(self, data):  # type: (bytes) -> bytes
        pass

    @abc.abstractmethod
    def native_finish(self):        # type: () -> bytes
        pass


class AesStreamCryptorImpl(AesStreamCryptor):
    def __init__(self, is_encrypt, iv, key):
        super().__init__(is_encrypt, len(iv))
        cipher = Cipher(AES(key), CBC(iv), backend=_CRYPTO_BACKEND)
        self.cryptor = cipher.encryptor() if is_encrypt else cipher.decryptor()  # type: CipherContext

    def native_update(self, data):
        return self.cryptor.update(data)

    def native_finish(self):
        return self.cryptor.finalize()


def aes_v1_stream_decryptor(iv, key):
    return AesStreamCryptorImpl(False, iv, key)


def aes_v1_stream_encryptor(iv, key):
    return AesStreamCryptorImpl(True, iv, key)
