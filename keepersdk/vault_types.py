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
from typing import Optional, List, Set, Dict

import logging
import json

from . import crypto, utils
from .errors import KeeperError


class CustomField:
    def __init__(self):
        self.name = ''
        self.value = ''
        self.type = ''


class AttachmentFileThumb:
    def __init__(self):
        self.id = ''
        self.type = ''
        self.size = 0


class AttachmentFile:
    def __init__(self):
        self.id = ''
        self.key = b''
        self.name = ''
        self.title = ''
        self.type = ''
        self.size = 0
        self.last_modified = 0
        self.thumbnails = []    # type: List[AttachmentFileThumb]


class RecordPermission:
    def __init__(self):
        self.shared_folder_uid = None
        self.can_share = False
        self.can_edit = False


class PasswordRecord:
    def __init__(self):
        self.record_uid = ""
        self.revision = 0
        self.title = ''
        self.login = ''
        self.password = ''
        self.link = ''
        self.notes = ''
        self.custom = []            # type: List[CustomField]
        self.attachments = []       # type: List[AttachmentFile]
        self.data = None            # type: Optional[dict]
        self.extra = None           # type: Optional[dict]
        self.udata = None           # type: Optional[dict]
        self.record_key = None      # type: Optional[bytes]
        self.permissions = []       # type: List[RecordPermission]
        self.owner = False
        self.shared = False

    def get_field(self, name):
        # type: (str) -> Optional[CustomField]
        for cf in self.custom:
            if cf.name == name:
                return cf
        return None

    def set_field(self, name, value):
        # type: (str, str) -> CustomField
        cf = self.get_field(name)
        if not cf:
            cf = CustomField()
            cf.name = name
            self.custom.append(cf)
        cf.value = value
        return cf

    def remove_field(self, name):
        self.custom = [x for x in self.custom if x.name != name]

    @staticmethod
    def dump(record):       # type: (PasswordRecord) -> dict
        data = {
            'title': record.title,
            'secret1': record.login,
            'secret2': record.password,
            'link': record.link,
            'notes': record.notes,
            'custom': []
        }
        for custom in record.custom:
            data['custom'].append({
                'name': custom.name,
                'value': custom.value,
                'type': custom.type
            })

        extra = record.extra.copy() if record.extra else None       # type: Optional[dict]
        udata = record.udata.copy if record.udata else None         # type: Optional[dict]
        if record.attachments:
            if not extra:
                extra = {}
            if not udata:
                udata = {}

            file_ids = []
            udata['file_ids'] = file_ids
            files = []
            extra['files'] = files

            for atta in record.attachments:
                file_ids.append(atta.id)
                attachment = {
                    'id': atta.id,
                    'name': atta.name,
                    'key': utils.base64_url_encode(atta.key)
                }
                if atta.size > 0:
                    attachment['size'] = atta.size
                if atta.title:
                    attachment['title'] = atta.title
                if atta.type:
                    attachment['type'] = atta.type
                if atta.thumbnails:
                    attachment['thumbnails'] = []
                    for thumb in atta.thumbnails:
                        th = {'id': thumb.id}
                        if thumb.size > 0:
                            th['size'] = thumb.size
                        if thumb.type:
                            th['type'] = thumb.type
                        attachment['thumbnails'].append(th)
                        file_ids.append(file_ids)
                files.append(attachment)
        else:
            if extra:
                if 'files' in extra:
                    del extra['files']
            if udata:
                if 'file_ids' in udata:
                    del udata['file_ids']

        result = {}
        if data:
            result['data'] = data
        if extra:
            result['extra'] = extra
        if udata:
            result['udata'] = udata

        return result

    @staticmethod
    def load(rec_dict, record_key):
        # type: (dict, bytes) -> PasswordRecord
        record_uid = rec_dict['record_uid']
        record = PasswordRecord()
        record.record_uid = record_uid
        record.record_key = record_key
        record.revision = rec_dict['revision']
        record.shared = rec_dict.get('shared') or False
        data = utils.base64_url_decode(rec_dict['data'])
        data = crypto.decrypt_aes_v1(data, record_key)
        record.data = json.loads(data.decode('utf-8'))
        record.title = record.data.get('title') or ''
        record.login = record.data.get('secret1') or ''
        record.password = record.data.get('secret2') or ''
        record.link = record.data.get('link') or ''
        record.notes = record.data.get('notes') or ''
        if 'custom' in record.data:
            for custom in record.data['custom']:
                custom_field = CustomField()
                custom_field.name = custom.get('name') or ''
                custom_field.value = custom.get('value') or ''
                custom_field.type = custom.get('type') or ''
                record.custom.append(custom_field)
        if 'extra' in rec_dict:
            extra = utils.base64_url_decode(rec_dict['extra'])
            extra = crypto.decrypt_aes_v1(extra, record_key)
            record.extra = json.loads(extra.decode('utf-8'))
            if 'files' in record.extra:
                for file_dict in record.extra['files']:
                    if 'key' in file_dict:
                        file = AttachmentFile()
                        file.id = file_dict['id']
                        file.key = utils.base64_url_decode(file_dict['key'])
                        file.name = file_dict.get('name') or ''
                        file.title = file_dict.get('title') or ''
                        file.size = file_dict.get('size') or 0
                        file.type = file_dict.get('type') or ''
                        if 'thumbnails' in file_dict:
                            for thumb_dict in file_dict['thumbnails']:
                                thumb = AttachmentFileThumb()
                                thumb.id = thumb_dict['id']
                                thumb.size = thumb_dict.get('size') or 0
                                thumb.type = thumb_dict.get('type') or ''
                                file.thumbnails.append(thumb)
                        record.attachments.append(file)
        if 'udata' in rec_dict:
            record.udata = rec_dict['udata']

        return record


class SharedFolderUser:
    def __init__(self, username):
        self.username = username
        self.manage_records = False
        self.manage_users = False


class SharedFolderPermission:
    def __init__(self):
        self.team_uid = None
        self.manage_records = False
        self.manage_users = False


class SharedFolder:
    def __init__(self):
        self.shared_folder_uid = ""
        self.name = ""
        self.default_manage_records = False
        self.default_manage_users = False
        self.default_can_edit = False
        self.default_can_share = False
        self.record_keys = {}           # type: Dict[str, bytes]
        self.users = {}                 # type: Dict[str, SharedFolderUser]
        self.teams = {}                 # type: Dict[str, str]
        self.shared_folder_key = None   # type: Optional[bytes]
        self.permissions = []           # type: List[SharedFolderPermission]
        self.record_permissions = {}    # type: Dict[str, RecordPermission]

    @staticmethod
    def parse(sf_dict, shared_folder_key):
        shared_folder_uid = sf_dict['shared_folder_uid']
        shared_folder = SharedFolder()
        shared_folder.shared_folder_uid = shared_folder_uid
        shared_folder.shared_folder_key = shared_folder_key
        shared_folder.default_manage_records = sf_dict.get('default_manage_records') or False
        shared_folder.default_manage_users = sf_dict.get('default_manage_users') or False
        shared_folder.default_can_edit = sf_dict.get('default_can_edit') or False
        shared_folder.default_can_share = sf_dict.get('default_can_share') or False
        try:
            enc_name = utils.base64_url_decode(sf_dict['name'])
            dec_name = crypto.decrypt_aes_v1(enc_name, shared_folder_key)
            shared_folder.name = dec_name.decode('utf-8')
        except Exception as e:
            shared_folder.name = shared_folder_uid
            logging.debug('Error decrypting Shared Folder %s name: %s', shared_folder_uid, e)

        if 'shared_folder_key' in sf_dict:
            sfp = SharedFolderPermission()
            sfp.manage_records = sf_dict['manage_records']
            sfp.manage_users = sf_dict['manage_users']
            shared_folder.permissions.append(sfp)

        if 'teams' in sf_dict:
            for sft in sf_dict['teams']:
                team_uid = sft['team_uid']
                shared_folder.teams[team_uid] = sft['name']
                sfp = SharedFolderPermission()
                sfp.team_uid = team_uid
                sfp.manage_records = sft['manage_records']
                sfp.manage_users = sft['manage_users']
                shared_folder.permissions.append(sfp)

        if 'users' in sf_dict:
            for sfu in sf_dict['users']:
                username = sfu['username']
                shared_folder_user = SharedFolderUser(username)
                shared_folder_user.manage_users = sfu['manage_users']
                shared_folder_user.manage_records = sfu['manage_records']
                shared_folder.users[username] = shared_folder_user

        if 'records' in sf_dict:
            for sfr in sf_dict['records']:
                record_uid = sfr['record_uid']
                record_key = utils.base64_url_decode(sfr['record_key'])
                try:
                    record_key = crypto.decrypt_aes_v1(record_key, shared_folder.shared_folder_key)
                    shared_folder.record_keys[record_uid] = record_key
                except Exception as e:
                    logging.info('Decrypt shared folder (%s) record (%s) key error: %s',
                                 shared_folder_uid, record_uid, e)

                record_permission = RecordPermission()
                record_permission.shared_folder_uid = shared_folder_uid
                record_permission.can_edit = sfr['can_edit']
                record_permission.can_share = sfr['can_share']
                shared_folder.record_permissions[record_uid] = record_permission
        return shared_folder


class Team:
    def __init__(self):
        self.team_uid = ''
        self.name = ''
        self.team_key = None        # type: Optional[bytes]
        self.private_key = None
        self.restrict_edit = False
        self.restrict_share = False
        self.restrict_view = False
        self.shared_folder_keys = {}    # type: Dict[str, bytes]

    @staticmethod
    def parse(team_dict, team_key):
        # type: (dict, bytes) -> Team
        team = Team()
        team.team_uid = team_dict['team_uid']
        team.team_key = team_key
        private_key = utils.base64_url_decode(team_dict['team_private_key'])
        private_key = crypto.decrypt_aes_v1(private_key, team.team_key)
        team.private_key = crypto.load_private_key(private_key)
        team.restrict_edit = team_dict.get('restrict_edit') or False
        team.restrict_view = team_dict.get('restrict_view') or False
        team.restrict_share = team_dict.get('restrict_share') or False
        if 'shared_folder_keys' in team_dict:
            for sfk in team_dict['shared_folder_keys']:
                shared_folder_uid = sfk['shared_folder_uid']
                key_type = sfk['key_type']
                key = utils.base64_url_decode(sfk['shared_folder_key'])
                try:
                    if key_type == 1:
                        key = crypto.decrypt_aes_v1(key, team.team_key)
                    elif key_type == 2:
                        key = crypto.decrypt_rsa(key, team.private_key)
                    else:
                        raise KeeperError('Unsupported shared folder key type: {0}'.format(key_type))
                    team.shared_folder_keys[shared_folder_uid] = key
                except Exception as e:
                    logging.warning('Error decrypting shared folder key in team %s: %s', team.team_uid, e)
        return team


class Folder:
    def __init__(self, uid):
        self.folder_uid = uid
        self.folder_type = ''
        self.name = ''
        self.parent_uid = None          # type: Optional[str]
        self.shared_folder_uid = None   # type: Optional[str]
        self.subfolders = set()         # type: Set[str]
        self.records = set()            # type: Set[str]


PersonalFolderUid = 'PersonalFolderUid'
