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


class StorageRecord:
    def __init__(self):
        self.record_uid = ''
        self.revision = 0
        self.client_modified_time = 0
        self.data = None
        self.extra = None
        self.udata = None
        self.shared = False
        self.owner = False

    def uid(self):
        return self.record_uid


class StorageNonSharedData:
    def __init__(self):
        self.record_uid = ''
        self.data = ''

    def uid(self):
        return self.record_uid


class StorageSharedFolder:
    def __init__(self):
        self.shared_folder_uid = ''
        self.revision = 0
        self.name = ''
        self.default_manage_records = False
        self.default_manage_users = False
        self.default_can_edit = False
        self.default_can_share = False

    def uid(self):
        return self.shared_folder_uid


class StorageFolder:
    def __init__(self):
        self.folder_uid = ''
        self.parent_uid = ''
        self.folder_type = ''
        self.folder_key = ''
        self.shared_folder_uid = ''
        self.revision = 0
        self.data = ''

    def uid(self):
        return self.folder_uid


class StorageTeam:
    def __init__(self):
        self.team_uid = ''
        self.name = ''
        self.team_key = ''
        self.key_type = 0
        self.team_private_key = ''
        self.restrict_edit = False
        self.restrict_share = False
        self.restrict_view = False

    def uid(self):
        return self.team_uid


class StorageRecordKey:
    def __init__(self):
        self.record_uid = ''
        self.shared_folder_uid = ''
        self.record_key = ''
        self.key_type = 0
        self.can_share = False
        self.can_edit = False

    def subject_uid(self):
        return self.record_uid

    def object_uid(self):
        return self.shared_folder_uid


class StorageSharedFolderKey:
    def __init__(self):
        self.shared_folder_uid = ''
        self.team_uid = ''
        self.key_type = 0
        self.shared_folder_key = ''

    def subject_uid(self):
        return self.shared_folder_uid

    def object_uid(self):
        return self.team_uid


class StorageSharedFolderPermission:
    def __init__(self):
        self.shared_folder_uid = ''
        self.user_uid = ''
        self.user_type = 0
        self.manage_records = False
        self.manage_users = False

    def subject_uid(self):
        return self.shared_folder_uid

    def object_uid(self):
        return self.user_uid


class StorageFolderRecordLink:
    def __init__(self):
        self.folder_uid = ''
        self.record_uid = ''

    def subject_uid(self):
        return self.folder_uid

    def object_uid(self):
        return self.record_uid


class UidLink:
    def __init__(self, subject_uid, object_uid):
        self._subject_uid = subject_uid
        self._object_uid = object_uid

    def subject_uid(self):
        return self._subject_uid

    def object_uid(self):
        return self._object_uid


class IEntityStorage(abc.ABC):
    @abc.abstractmethod
    def get(self, uid):
        pass

    @abc.abstractmethod
    def put(self, data):
        pass

    @abc.abstractmethod
    def delete(self, uid):
        pass

    @abc.abstractmethod
    def get_all(self):
        pass

    @abc.abstractmethod
    def clear(self):
        pass


class IPredicateStorage(abc.ABC):
    @abc.abstractmethod
    def put(self, data):
        pass

    @abc.abstractmethod
    def delete_link(self, link):
        pass

    @abc.abstractmethod
    def get_links_for_subject(self, subject_uid):
        pass

    @abc.abstractmethod
    def get_links_for_object(self, object_uid):
        pass

    @abc.abstractmethod
    def get_all_links(self):
        pass

    @abc.abstractmethod
    def clear(self):
        pass

    def delete_object(self, object_uid):
        links = [x for x in self.get_links_for_object(object_uid)]
        for link in links:
            self.delete_link(link)

    def delete_subject(self, subject_uid):
        links = [x for x in self.get_links_for_subject(subject_uid)]
        for link in links:
            self.delete_link(link)

    def delete(self, subject_uid, object_uid):
        self.delete_link(UidLink(subject_uid, object_uid))


class IKeeperStorage(abc.ABC):
    def __init__(self):
        self.revision = 0

    @property
    @abc.abstractmethod
    def personal_scope_uid(self):
        pass

    @property
    @abc.abstractmethod
    def records(self):
        pass

    @property
    @abc.abstractmethod
    def shared_folders(self):
        pass

    @property
    @abc.abstractmethod
    def teams(self):
        pass

    @property
    @abc.abstractmethod
    def non_shared_data(self):
        pass

    @property
    @abc.abstractmethod
    def record_keys(self):
        pass

    @property
    @abc.abstractmethod
    def shared_folder_keys(self):
        pass

    @property
    @abc.abstractmethod
    def shared_folder_permissions(self):
        pass

    @property
    @abc.abstractmethod
    def folders(self):
        pass

    @property
    @abc.abstractmethod
    def folder_records(self):
        pass

    @abc.abstractmethod
    def clear(self):
        pass


class InMemoryItemStorage(IEntityStorage):
    def __init__(self):
        self._items = {}

    def get(self, uid):
        return self._items.get(uid)

    def put(self, data):
        uid = data.uid()
        if uid in self._items:
            if self._items[uid] is data:
                return
        self._items[uid] = data

    def delete(self, uid):
        if uid in self._items:
            del self._items[uid]

    def get_all(self):
        for item in self._items.values():
            yield item

    def clear(self):
        self._items.clear()


class InMemoryLinkStorage(IPredicateStorage):
    def __init__(self):
        self._links = {}

    def clear(self):
        self._links.clear()

    def put(self, data):
        subject_uid = data.subject_uid()
        object_uid = data.object_uid()
        if subject_uid not in self._links:
            self._links[subject_uid] = {}
        self._links[subject_uid][object_uid] = data

    def delete_link(self, link):
        subject_uid = link.subject_uid()
        if subject_uid in self._links:
            object_uid = link.object_uid()
            if object_uid in self._links[subject_uid]:
                del self._links[subject_uid][object_uid]

    def get_all_links(self):
        for subj in self._links.values():
            for data in subj.values():
                yield data

    def get_links_for_subject(self, subject_uid):
        if subject_uid in self._links:
            for data in self._links[subject_uid].values():
                yield data

    def get_links_for_object(self, object_uid):
        for subj in self._links.values():
            if object_uid in subj:
                yield subj[object_uid]

    def get(self, subject_uid, object_uid):
        if subject_uid in self._links:
            if object_uid in self._links[subject_uid]:
                return self._links[subject_uid][object_uid]


class InMemoryVaultStorage(IKeeperStorage):
    def __init__(self):
        super().__init__()

        self._records = InMemoryItemStorage()
        self._shared_folders = InMemoryItemStorage()
        self._teams = InMemoryItemStorage()
        self._non_shared_data = InMemoryItemStorage()

        self._record_keys = InMemoryLinkStorage()
        self._shared_folder_keys = InMemoryLinkStorage()
        self._shared_folder_permissions = InMemoryLinkStorage()

        self._folders = InMemoryItemStorage()
        self._folder_records = InMemoryLinkStorage()

    @property
    def personal_scope_uid(self):
        return 'PersonalScopeUid'

    @property
    def records(self):
        return self._records

    @property
    def shared_folders(self):
        return self._shared_folders

    @property
    def teams(self):
        return self._teams

    @property
    def non_shared_data(self):
        return self._non_shared_data

    @property
    def record_keys(self):
        return self._record_keys

    @property
    def shared_folder_keys(self):
        return self._shared_folder_keys

    @property
    def shared_folder_permissions(self):
        return self._shared_folder_permissions

    @property
    def folders(self):
        return self._folders

    @property
    def folder_records(self):
        return self._folder_records

    def clear(self):
        self.revision = 0
        self._records.clear()
        self._shared_folders.clear()
        self._teams.clear()
        self._non_shared_data.clear()

        self._record_keys.clear()
        self._shared_folder_keys.clear()
        self._shared_folder_permissions.clear()

        self._folders.clear()
        self._folder_records.clear()
