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

import logging
import json

from . import crypto, utils


class CustomField:
    def __init__(self):
        self.name = ''
        self.value = ''
        self.type = ''


class ExtraField:
    def __init__(self):
        self.id = ''
        self.field_type = ''
        self.field_title = ''
        self.custom = {}


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
        self.thumbnails = []


class RecordPermission:
    def __init__(self):
        self.shared_folder_uid = None
        self.can_share = False
        self.can_edit = False


class PasswordRecord:
    def __init__(self):
        self.record_uid = ""
        self.title = ''
        self.login = ''
        self.password = ''
        self.link = ''
        self.notes = ''
        self.custom = []
        self.attachments = []
        self.extra_fields = []
        self.owner = False
        self.shared = False
        self.record_key = None

    def get_field(self, name):
        for cf in self.custom:
            if cf.name == name:
                return cf
        return None

    def set_field(self, name, value):
        cf = self.get_field(name)
        if not cf:
            cf = CustomField()
            cf.name = name
            self.custom.append(cf)
        cf.value = value
        return cf

    def remove_field(self, name):
        self.custom = [x for x in self.custom if x.name != name]

    def get_extra(self, field_type):
        for ef in self.extra_fields:
            if ef.field_type == field_type:
                return ef

    @staticmethod
    def load(store_record, record_key):
        record = PasswordRecord()
        record.record_uid = store_record.record_uid
        record.record_key = record_key
        record.shared = store_record.shared
        record.owner = store_record.owner

        enc_data = utils.base64_url_decode(store_record.data)
        dec_data = crypto.decrypt_aes_v1(enc_data, record_key)
        data = json.loads(dec_data.decode('utf-8'))    # type: dict
        record.title = data.get('title') or ''
        record.login = data.get('secret1') or ''
        record.password = data.get('secret2') or ''
        record.link = data.get('link') or ''
        record.notes = data.get('notes') or ''

        if 'custom' in data:
            for custom in data['custom']:
                custom_field = CustomField()
                custom_field.name = custom.get('name') or ''
                custom_field.value = custom.get('value') or ''
                custom_field.type = custom.get('type') or ''
                record.custom.append(custom_field)

        if store_record.extra:
            enc_extra = utils.base64_url_decode(store_record.extra)
            dec_extra = crypto.decrypt_aes_v1(enc_extra, record_key)
            extra = json.loads(dec_extra.decode('utf-8'))   # type: dict
            if 'files' in extra:
                for file_dict in extra['files']:
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
            if 'fields' in extra:
                for field_dict in extra['fields']:  # type: dict
                    field = ExtraField()
                    for k, v in field_dict.items():
                        if k == 'field_type':
                            field.field_type = v
                        elif k == 'id':
                            field.id = v
                        elif k == 'field_title':
                            field.field_title = v
                        else:
                            field.custom[k] = v

        return record

    @staticmethod
    def dump(record, extra=None, udata=None):
        result = {}

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
        result['data'] = data

        extra = extra or {}
        udata = udata or {}
        if record.attachments:
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

        if record.extra_fields:
            fields = []
            extra['fields'] = fields
            for field in record.extra_fields:
                field_dict = {
                    'field_type': field.field_title,
                    'id': field.id,
                    'field_title': field.field_title
                }
                if field.custom:
                    field_dict.update(field.custom)
                fields.append(field_dict)

        result['extra'] = extra
        result['udata'] = udata

        return result


class SharedFolderRecord:
    def __init__(self):
        self.record_uid = ''
        self.can_edit = False
        self.can_share = False


class SharedFolderPermission:
    def __init__(self):
        self.user_id = ''
        self.user_type = 0
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
        self.shared_folder_key = None
        self.user_permissions = []
        self.record_permissions = []

    @staticmethod
    def load(store_sf, records, users, shared_folder_key):
        shared_folder_uid = store_sf.shared_folder_uid
        shared_folder = SharedFolder()
        shared_folder.shared_folder_uid = shared_folder_uid
        shared_folder.shared_folder_key = shared_folder_key
        shared_folder.default_manage_records = store_sf.default_manage_records
        shared_folder.default_manage_users = store_sf.default_manage_users
        shared_folder.default_can_edit = store_sf.default_can_edit
        shared_folder.default_can_share = store_sf.default_can_share
        try:
            enc_name = utils.base64_url_decode(store_sf.name)
            dec_name = crypto.decrypt_aes_v1(enc_name, shared_folder_key)
            shared_folder.name = dec_name.decode('utf-8')
        except Exception as e:
            shared_folder.name = shared_folder_uid
            logging.debug('Error decrypting Shared Folder %s name: %s', shared_folder_uid, e)

        for up in users:
            sf_p = SharedFolderPermission()
            sf_p.user_type = up.user_type
            sf_p.user_id = up.user_uid
            sf_p.manage_records = up.manage_records
            sf_p.manage_users = up.manage_users
            shared_folder.user_permissions.append(sf_p)

        for rp in records:
            sf_r = SharedFolderRecord()
            sf_r.record_uid = rp.record_uid
            sf_r.can_edit = rp.can_edit
            sf_r.can_share = rp.can_share
            shared_folder.record_permissions.append(sf_r)

        return shared_folder


class EnterpriseTeam:
    def __init__(self):
        self.team_uid = ''
        self.name = ''
        self.restrict_edit = False
        self.restrict_share = False
        self.restrict_view = False
        self.team_key = None
        self.private_key = None

    @staticmethod
    def load(store_team, team_key):
        team = EnterpriseTeam()
        team.team_uid = store_team.team_uid
        team.team_key = team_key
        team.restrict_edit = store_team.restrict_edit
        team.restrict_view = store_team.restrict_view
        team.restrict_share = store_team.restrict_share
        private_key = utils.base64_url_decode(store_team.team_private_key)
        private_key = crypto.decrypt_aes_v1(private_key, team_key)
        team.private_key = crypto.load_private_key(private_key)
        return team


class Folder:
    def __init__(self):
        self.folder_uid = ''
        self.folder_type = ''
        self.name = ''
        self.parent_uid = None
        self.shared_folder_uid = None
        self.subfolders = set()
        self.records = set()
