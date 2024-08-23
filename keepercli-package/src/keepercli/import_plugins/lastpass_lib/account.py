from typing import Optional, List
from .shared_folder import LastpassSharedFolder

class Account(object):
    def __init__(self, account_id: str, name: bytes, username: bytes, password: bytes, url: bytes, group,
                 notes = None, shared_folder: Optional[LastpassSharedFolder] = None,
                 attach_key = None, totp_secret = None, totp_url = None):
        self.id = account_id
        self.name = name
        self.username = username
        self.password = password
        self.url = url
        self.group = group
        self.notes = notes
        self.shared_folder = shared_folder
        self.attach_key = attach_key
        self.totp_secret = totp_secret
        self.totp_url = totp_url
        self.last_modified = 0
        self.custom_fields: List[CustomField] = []


class CustomField(object):
    def __init__(self, f_name, f_type, f_value, checked):
        self.name = f_name
        self.type = f_type
        self.value = f_value
        self.checked = checked
