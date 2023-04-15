#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from typing import Dict, Any, Callable, Optional, Union

from .types import IEntityStorage, ILinkStorage, IUidLink, IUid

KeyType = Union[str, int, bytes]
GetUid = Callable[[Any], KeyType]


class InMemoryEntityStorage(IEntityStorage):
    def __init__(self, get_uid=None):   # type: (Optional[GetUid]) -> None
        self._items = {}
        self.get_uid = get_uid

    def get_entity(self, uid):
        return self._items.get(uid)

    def get_all(self):
        for item in self._items.values():
            yield item

    def put_entities(self, entities):
        for entity in entities:
            if isinstance(entity, IUid):
                uid = entity.uid()
            elif self.get_uid is not None:
                uid = self.get_uid(entity)
            else:
                raise ValueError(f'Cannot get UID for class {type(entity)}')

            if uid in self._items:
                if self._items[uid] is entity:
                    return
            self._items[uid] = entity

    def delete_uids(self, uids):
        for uid in uids:
            if uid in self._items:
                del self._items[uid]

    def clear(self):
        self._items.clear()


class InMemoryLinkStorage(ILinkStorage):
    def __init__(self, get_subject=None, get_object=None):    # type: (Optional[GetUid], Optional[GetUid]) -> None
        self.get_subject = get_subject
        self.get_object = get_object
        self._links = {}   # type: Dict[KeyType, Dict[KeyType, Any]]

    def put_links(self, links):
        for link in links:
            if isinstance(link, IUidLink):
                subject_uid = link.subject_uid()
                object_uid = link.object_uid()
            elif self.get_subject and self.get_object:
                subject_uid = self.get_subject(link)
                object_uid = self.get_object(link)
            else:
                raise ValueError(f'Cannot get subject and object UIDs for class {type(link)}')

            if subject_uid not in self._links:
                self._links[subject_uid] = {}
            self._links[subject_uid][object_uid] = link

    def delete_links(self, links):
        for link in links:
            if isinstance(link, IUidLink):
                subject_uid = link.subject_uid()
                object_uid = link.object_uid()
            elif isinstance(link, (list, tuple)) and len(link) == 2:
                subject_uid = link[0]
                object_uid = link[1]
            elif self.get_subject and self.get_object:
                subject_uid = self.get_subject(link)
                object_uid = self.get_object(link)
            else:
                raise ValueError('Unsupported link type')
            if subject_uid in self._links:
                if object_uid in self._links[subject_uid]:
                    del self._links[subject_uid][object_uid]

    def delete_links_for_subjects(self, subject_uids):
        for subject_uid in subject_uids:
            if subject_uid in self._links:
                del self._links[subject_uid]

    def delete_links_for_objects(self, object_uids):
        for objects in self._links.values():
            for object_uid in object_uids:
                if object_uid in objects:
                    del objects[object_uid]

    def get_links_for_subject(self, subject_uid):
        if subject_uid in self._links:
            objects = self._links[subject_uid]
            for data in objects.values():
                yield data

    def get_links_for_object(self, object_uid):
        for subj in self._links.values():
            if object_uid in subj:
                yield subj[object_uid]

    def get_all_links(self):
        for subj in self._links.values():
            for data in subj.values():
                yield data

    def clear(self):
        self._links.clear()
