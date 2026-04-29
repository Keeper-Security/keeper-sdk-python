import base64
import logging
import math
import re
import sys
import time
from typing import Iterator, Callable, Optional
from urllib.parse import urlparse
from pathlib import Path
from . import crypto


def get_logger(name: str='keeper.sdk') -> logging.Logger:
    return logging.getLogger(name)


def generate_uid() -> str:
    b = crypto.get_random_bytes(16)
    if (b[0] & 0xf8) == 0xf8:
        b = bytes([b[0] & 0x7f]) + b[1:]
    return base64_url_encode(b)


def generate_aes_key() -> bytes:
    return crypto.get_random_bytes(32)


def current_milli_time() -> int:
    return int(round(time.time() * 1000))


def base64_url_decode(s: str) -> bytes:
    if len(s) == 0:
        return b''
    return base64.urlsafe_b64decode(s + '==')


def base64_url_encode(b: bytes) -> str:
    if len(b) == 0:
        return ''
    bs = base64.urlsafe_b64encode(b)
    return bs.rstrip(b'=').decode('utf-8')


def decrypt_encryption_params(encryption_params: bytes, password: str) -> bytes:
    if len(encryption_params) != 100:
        raise Exception('Invalid encryption params: bad params length')

    _ = int.from_bytes(encryption_params[0:1], byteorder='big', signed=False)
    iterations = int.from_bytes(encryption_params[1:4], byteorder='big', signed=False)
    salt = encryption_params[4:20]
    encrypted_data_key = encryption_params[20:]

    key = crypto.derive_key_v1(password, salt, iterations)
    decrypted_data_key = crypto.decrypt_aes_v1(encrypted_data_key, key, use_padding=False)

    # validate the key is formatted correctly
    if len(decrypted_data_key) != 64:
        raise Exception('Invalid data key length')

    if decrypted_data_key[:32] != decrypted_data_key[32:]:
        raise Exception('Invalid data key: failed mirror verification')

    return decrypted_data_key[:32]


def create_encryption_params(password: str, salt: bytes, iterations: int, data_key: bytes) -> bytes:
    key = crypto.derive_key_v1(password, salt, iterations)
    enc_iter = int.to_bytes(iterations, length=3, byteorder='big', signed=False)
    enc_iv = crypto.get_random_bytes(16)
    enc_data_key = crypto.encrypt_aes_v1(data_key * 2, key, iv=enc_iv, use_padding=False)
    return b'\x01' + enc_iter + salt + enc_data_key


def create_auth_verifier(password: str, salt: bytes, iterations: int) -> bytes:
    derived_key = crypto.derive_key_v1(password, salt, iterations)
    enc_iter = int.to_bytes(iterations, length=3, byteorder='big', signed=False)
    return b'\x01' + enc_iter + salt + derived_key


_breach_watch_key = base64_url_decode('phl9kdMA_gkJkSfeOYWpX-FOyvfh-APhdSFecIDMyfI')
def breach_watch_hash(password: str) -> bytes:
    return crypto.hmac_sha512(_breach_watch_key, f'password:{password}'.encode('utf-8'))


VALID_URL_SCHEME_CHARS = '+-.:'


def is_url(test_str: str) -> bool:
    if not isinstance(test_str, str):
        return False
    url_parts = test_str.split('://')
    url_scheme = url_parts[0]
    valid_scheme = all((c.isalnum() or c in VALID_URL_SCHEME_CHARS) for c in url_scheme)
    if len(test_str.split()) == 1 and len(url_parts) > 1 and valid_scheme:
        return True
    else:
        return False


EMAIL_PATTERN = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
email_pattern = re.compile(EMAIL_PATTERN)


def is_email(test_str: str) -> bool:
    return email_pattern.match(test_str) is not None


def url_strip(url: str) -> str:
    if not url:
        return ''
    try:
        result = urlparse(url)
        return result.netloc + result.path
    except Exception as e:
        get_logger().debug('"url_strip" error: %s', e)
        return ''


def chunk_text(text: str, func: Callable[[str], bool]) -> Iterator[str]:
    acc = ''
    for x in text:
        if func(x):
            acc += x
        else:
            if acc:
                yield acc
                acc = ''
    if acc:
        yield acc


def offset_char(text: str, func: Callable[[str, str], int]) -> Iterator[int]:
    if not text:
        return
    prev = text[0]
    for ch in text[1:]:
        yield func(prev, ch)
        prev = ch


def password_score(password: str) -> int:
    score = 0
    if not password:
        return score
    if not isinstance(password, str):
        return score

    total = len(password)
    uppers = 0
    lowers = 0
    digits = 0
    symbols = 0
    for x in password:
        if x.isupper():
            uppers += 1
        elif x.islower():
            lowers += 1
        elif x.isdecimal():
            digits += 1
        else:
            symbols += 1

    ds = digits + symbols
    if not password[0].isalpha():
        ds -= 1
    if not password[-1].isalpha():
        ds -= 1
    if ds < 0:
        ds = 0

    score += total * 4
    if uppers > 0:
        score += (total-uppers) * 2
    if lowers > 0:
        score += (total-lowers) * 2
    if digits > 0:
        score += digits * 4
    score += symbols * 6
    score += ds * 2

    variance = 0
    if uppers > 0:
        variance += 1
    if lowers > 0:
        variance += 1
    if digits > 0:
        variance += 1
    if symbols > 0:
        variance += 1
    if total >= 8 and variance >= 3:
        score += (variance + 1) * 2

    if digits + symbols == 0:
        score -= total

    if uppers + lowers + symbols == 0:
        score -= total

    rep_inc = 0
    pwd_len = len(password)
    rep_count = 0
    for i in range(pwd_len):
        char_exists = False
        for j in range(pwd_len):
            if i != j and password[i] == password[j]:
                char_exists = True
                rep_inc += pwd_len // abs(i - j)
        if char_exists:
            rep_count += 1
            unq_count = pwd_len - rep_count
            rep_inc = math.ceil(rep_inc if unq_count == 0 else rep_inc / unq_count)

    if rep_count > 0:
        score -= rep_inc

    count = 0
    consec: Callable[[str], bool]
    for consec in [str.isupper, str.islower, str.isdecimal]:
        for chunk in chunk_text(password, consec):
            length = len(chunk)
            if length >= 2:
                count += length - 1
    if count > 0:
        score -= 2 * count

    count = 0
    for cnt, seq in [(26, str.isalpha), (10, str.isdecimal)]:
        cnt = 0
        for chunk in chunk_text(password.lower(), seq):
            if len(chunk) >= 3:
                offsets = [x if x >= 0 else x + cnt for x in offset_char(chunk, lambda y, z: ord(y) - ord(z))]
                op = offsets[0]
                for oc in offsets[1:]:
                    if oc == op:
                        if op != 0:
                            count += 1
                    else:
                        op = oc

    symbol_lookup = {x[1]: x[0] for x in enumerate('!@#$%^&*()_+[]\\{}|;\':\",./<>?')}
    cnt = 0
    for chunk in chunk_text(password, symbol_lookup.__contains__):
        if len(chunk) >= 3:
            offsets = [x if x >= 0 else x + cnt
                       for x in offset_char(chunk, lambda y, z: symbol_lookup[y] - symbol_lookup[z])]
            op = offsets[0]
            for oc in offsets[1:]:
                if oc == op:
                    if op != 0:
                        count += 1
                else:
                    op = oc

    if count > 0:
        score -= 3 * count

    return score if 0 <= score <= 100 else 0 if score < 0 else 100


def size_to_str(size: Optional[int]) -> str:
    if isinstance(size, (int, float)):
        if size < 2000:
            return f'{size} b'
        sz = float(size)
        sz = sz / 1024
        if sz < 1000:
            return f'{sz:.2f} Kb'
        sz = sz / 1024
        if sz < 1000:
            return f'{sz:.2f} Mb'
        sz = sz / 1024
        return f'{sz:,.2f} Gb'
    elif isinstance(size, str):
        return size
    elif size:
        return str(size)
    return ''


# SEARCHABLE_CHARACTERS = {x for x in '\'"`-_+$@%^&'}


def tokenize_searchable_text(text: str) -> Iterator[str]:
    if isinstance(text, str) and len(text) > 0:
        return (x.casefold() for x in text.split())
    else:
        return iter(())


def get_default_path():
    default_path = Path.home().joinpath('.keeper')
    default_path.mkdir(parents=True, exist_ok=True)
    return default_path


def get_ssl_cert_file():
    """Get SSL certificate file path, preferring system CA store for corporate environments like Zscaler"""
    import ssl
    import platform
    import certifi
    import os
    
    # Allow user to override via environment variable
    user_cert_file = os.getenv('KEEPER_SSL_CERT_FILE')
    if user_cert_file:
        if user_cert_file.lower() == 'system':
            pass  # Continue with system detection below
        elif user_cert_file.lower() == 'certifi':
            return certifi.where()
        elif user_cert_file.lower() == 'none' or user_cert_file.lower() == 'false':
            return False  # Disable SSL verification
        elif os.path.exists(user_cert_file):
            return user_cert_file
        else:
            # Don't use logging here as it can interfere with main logging config
            print(f"Warning: SSL cert file specified in KEEPER_SSL_CERT_FILE not found: {user_cert_file}", file=sys.stderr)
    
    # Try to use system CA store first for corporate environments
    try:
        # On macOS, try Homebrew certificates first (better for corporate environments like Zscaler)
        if platform.system() == 'Darwin':
            system_ca_paths = [
                '/opt/homebrew/etc/ca-certificates/cert.pem',  # Homebrew CA bundle (best for Zscaler)
                '/usr/local/etc/ssl/cert.pem',  # Homebrew SSL (older location)
                '/etc/ssl/cert.pem',  # macOS system CA bundle
            ]
            for ca_path in system_ca_paths:
                if os.path.exists(ca_path):
                    return ca_path
        
        # On Linux/Unix systems
        elif platform.system() == 'Linux':
            system_ca_paths = [
                '/etc/ssl/certs/ca-certificates.crt',  # Debian/Ubuntu
                '/etc/pki/tls/certs/ca-bundle.crt',    # RHEL/CentOS
                '/etc/ssl/ca-bundle.pem',              # OpenSUSE
                '/etc/ssl/cert.pem',                   # Generic
            ]
            for ca_path in system_ca_paths:
                if os.path.exists(ca_path):
                    return ca_path
        
        # Try to get default SSL context locations
        try:
            default_locations = ssl.get_default_verify_paths()
            if default_locations.cafile and os.path.exists(default_locations.cafile):
                return default_locations.cafile
            if default_locations.capath and os.path.exists(default_locations.capath):
                return default_locations.capath
        except:
            pass
            
    except Exception:
        pass
    
    # Fall back to certifi if system CA not available
    return certifi.where()

def ssl_aware_request(method, url, **kwargs):
    """Make an SSL-aware HTTP request using system CA certificates when available"""
    import requests
    
    # Only set verify if not already specified
    if 'verify' not in kwargs:
        cert_file = get_ssl_cert_file()
        if cert_file is False:
            kwargs['verify'] = False
        elif cert_file:
            kwargs['verify'] = cert_file
        # If cert_file is None, let requests use its default
    
    return requests.request(method, url, **kwargs)


def ssl_aware_get(url, **kwargs):
    """SSL-aware GET request using system CA certificates when available"""
    return ssl_aware_request('GET', url, **kwargs)