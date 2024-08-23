import io
from base64 import b64decode
from io import RawIOBase, BufferedReader, TextIOWrapper
from typing import Iterator

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC, ECB

from keepersdk import crypto

# Chunk size must be a multiple of 256
# Two b64 decodes each requiring a multiple of four times multiple of 16 needed for AES decryption (4 * 16 * 4 = 256)
CHUNK_SIZE = 8 * 1024


def decode_aes256_base64_from_stream(stream: io.RawIOBase,
                                     encryption_key: bytes,
                                     chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
    """Decrypts base64 encoded AES-256 from file in chunks

    CHUNK_SIZE is read in but only 9/16 of CHUNK_SIZE is yielded for every iteration due to b64 decoding
    """
    tail = stream.read(chunk_size)
    if tail is None:
        return

    aes_cipher: Cipher
    if tail[0] == ord('!'):
        iv = b64decode(tail[1:25])
        tail = tail[26:]
        aes_cipher = Cipher(AES(encryption_key), CBC(iv), backend=default_backend())
    else:
        aes_cipher = Cipher(AES(encryption_key), ECB(), backend=default_backend())

    decryptor = aes_cipher.decryptor()
    is_eof = False
    while not is_eof:
        if isinstance(tail, bytes):
            if len(tail) > chunk_size:
                data = tail[:chunk_size]
                tail = tail[chunk_size:]
            else:
                data = tail + (stream.read(chunk_size - len(tail)) or b'')
                tail = None
        else:
            data = stream.read(chunk_size) or b''
        is_eof = len(data) < chunk_size
        data = decryptor.update(b64decode(data))
        if is_eof:
            data += decryptor.finalize()
            data = crypto.unpad_data(data)
        yield b64decode(data)


class LastpassAttachmentReader(RawIOBase):
    """A RawIOBase reader that decrypts and decodes the input stream of a Lastpass attachment"""

    def __init__(self, attachment):
        self.attachment = attachment
        self.encrypted_stream = open(attachment.tmpfile, 'rb')

        key = attachment.parent.attach_key
        self.decryption_generator = decode_aes256_base64_from_stream(self.encrypted_stream, key)
        self.leftover = None
        self.size = 0

    def readable(self):
        return True

    def readinto(self, b):
        try:
            buf_len = len(b)
            chunk = self.leftover or next(self.decryption_generator)
            output = chunk[:buf_len]
            self.leftover = chunk[buf_len:]
            ret_len = len(output)
            b[:ret_len] = output
            self.size += ret_len
            return ret_len
        except StopIteration:
            return 0

    def close(self):
        self.encrypted_stream.close()
        self.attachment.size = self.size

    @classmethod
    def get_buffered_reader(cls, attachment):
        return BufferedReader(cls(attachment))

    @classmethod
    def get_text_reader(cls, attachment, **kwargs):
        buffered_reader = cls.get_buffered_reader(attachment)
        return TextIOWrapper(buffered_reader, **kwargs)
