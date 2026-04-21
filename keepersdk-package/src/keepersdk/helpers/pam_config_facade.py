
from typing import Any, Dict, List, Optional

from ..vault.record_facades import TypedRecordFacade, string_getter
from ..vault import vault_record, record_types


class PamConfigurationRecordFacade(TypedRecordFacade):
    _file_ref_getter = string_getter('_file_ref')

    def __init__(self):
        super(PamConfigurationRecordFacade, self).__init__()
        self._pam_resources = None
        self._port_mapping = None
        self._file_ref = None

    def load_typed_fields(self):
        if self.record:
            self._pam_resources = next((x for x in self.record.fields if x.type == 'pamResources'), None)
            if not self._pam_resources:
                self._pam_resources = vault_record.TypedField.create_field(field_type='pamResources', field_label='pamResources', required=False)
                self.record.fields.append(self._pam_resources)

            if len(self._pam_resources.value) > 0:
                if not isinstance(self._pam_resources.value[0], dict):
                    self._pam_resources.value.clear()

            if len(self._pam_resources.value) == 0:
                if 'pamResources' in record_types.FieldTypes and isinstance(record_types.FieldTypes['pamResources'].value, dict):
                    value = record_types.FieldTypes['pamResources'].value.copy()
                else:
                    value = {}
                self._pam_resources.value.append(value)

            self._port_mapping = next((x for x in self.record.fields
                                       if x.type == 'multiline' and x.label == 'portMapping'), None)
            if self._port_mapping is None:
                self._port_mapping = vault_record.TypedField.create_field(field_type='multiline', field_label='portMapping', required=False)
                self.record.fields.append(self._port_mapping)

            self._file_ref = next((x for x in self.record.fields if x.type == 'fileRef' and x.label == 'rotationScripts'), None)
            if self._file_ref is None:
                self._file_ref = vault_record.TypedField.create_field(field_type='fileRef', field_label='rotationScripts', required=False)
                self.record.fields.append(self._file_ref)
        else:
            self._pam_resources = None
            self._port_mapping = None
            self._file_ref = None

        super(PamConfigurationRecordFacade, self).load_typed_fields()

    def _pam_resources_dict(self) -> Optional[Dict[str, Any]]:
        """pamResources stores controllerUid, folderUid, and resourceRef in value[0]."""
        if not self._pam_resources or not self._pam_resources.value:
            return None
        v0 = self._pam_resources.value[0]
        return v0 if isinstance(v0, dict) else None

    @property
    def controller_uid(self) -> str:
        d = self._pam_resources_dict()
        if not d:
            return ''
        return d.get('controllerUid') or ''

    @controller_uid.setter
    def controller_uid(self, value: str) -> None:
        d = self._pam_resources_dict()
        if d is not None:
            d['controllerUid'] = value or ''

    @property
    def folder_uid(self) -> str:
        d = self._pam_resources_dict()
        if not d:
            return ''
        return d.get('folderUid') or ''

    @folder_uid.setter
    def folder_uid(self, value: str) -> None:
        d = self._pam_resources_dict()
        if d is not None:
            d['folderUid'] = value or ''

    @property
    def resource_ref(self) -> List[str]:
        d = self._pam_resources_dict()
        if not d:
            return []
        refs = d.get('resourceRef')
        if isinstance(refs, list):
            return refs
        return []

    @property
    def rotation_scripts(self):
        return PamConfigurationRecordFacade._file_ref_getter(self)
