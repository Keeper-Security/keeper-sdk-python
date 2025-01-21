import logging
from typing import Optional, List

from . import fetcher
from . import parser
from .exceptions import InvalidResponseError
from .shared_folder import LastpassSharedFolder
from .attachment import LastpassAttachment

class Vault(object):
    @classmethod
    def open_remote(cls, username: str, password: str, multifactor_password: Optional[str] = None,
                    client_id: Optional[str] = None) -> 'Vault':
        """Fetches a blob from the server and creates a vault"""
        session = fetcher.login(username, password, multifactor_password, client_id)
        blob = fetcher.fetch(session)
        encryption_key = blob.encryption_key(username, password)
        vault = cls(blob, encryption_key, session)
        return vault

    @classmethod
    def open_local(cls, blob_filename, username, password):
        """Creates a vault from a locally stored blob"""
        # TODO: read the blob here
        raise NotImplementedError()

    def __init__(self, blob, encryption_key, session, shared_folder_details=False):
        """This more of an internal method, use one of the static constructors instead"""
        chunks = parser.extract_chunks(blob)

        if not self.is_complete(chunks):
            raise InvalidResponseError('Blob is truncated')

        self.errors = set()
        self.shared_folders = []
        self.attachments: List[LastpassAttachment] = []
        self.accounts = self.parse_accounts(chunks, encryption_key)
        self.tmpdir = None
        self.session = session

        try:
            if self.shared_folders and shared_folder_details:
                for shared_folder in self.shared_folders:
                    members, teams, error = fetcher.fetch_shared_folder_members(session, shared_folder.id)
                    if error:
                        self.errors.add(error)
                        break
                    else:
                        shared_folder.members = members
                        shared_folder.teams = teams
        except Exception:
            pass

    def is_complete(self, chunks):
        return len(chunks) > 0 and chunks[-1].id == b'ENDM' and chunks[-1].payload == b'OK'

    def parse_accounts(self, chunks, encryption_key):
        accounts = []

        key = encryption_key
        rsa_private_key: Optional[bytes] = None
        shared_folder = None
        last_account = None
        for i in chunks:
            if i.id == b'ACCT':
                try:
                    last_account = parser.parse_ACCT(i, key, shared_folder)
                except Exception as e:
                    logging.debug('Account parse error: %s', e)
                    last_account = None
                if last_account:
                    accounts.append(last_account)
            elif i.id == b'PRIK':
                rsa_private_key = parser.parse_PRIK(i, encryption_key)
            elif i.id == b'SHAR':
                # After SHAR chunk all the following accounts are encrypted with a new key
                share = parser.parse_SHAR(i, encryption_key, rsa_private_key)
                key = share['encryption_key']
                shareid = share['id'].decode('utf-8')
                share_name = share['name'].decode('utf-8')
                share_name = share_name.strip()
                shared_folder = LastpassSharedFolder(shareid, share_name.decode('utf-8'))
                self.shared_folders.append(shared_folder)
            elif i.id == b'ATTA':
                attachment = parser.parse_ATTA(i)
                if attachment:
                    self.attachments.append(attachment)
            elif i.id in (b'ACFL', b'ACOF'):
                if last_account:
                    try:
                        cf = parser.parse_ACFL(i, key)
                        if cf:
                            last_account.custom_fields.append(cf)
                    except Exception as e:
                        logging.debug('Error parsing custom field ID: %s: %s', i.id.decode(), e)
            else:
                pass

        return accounts

    def cleanup(self):
        """Cleanup should be performed when finished with encrypted attachment files"""
        fetcher.logout(self.session)
