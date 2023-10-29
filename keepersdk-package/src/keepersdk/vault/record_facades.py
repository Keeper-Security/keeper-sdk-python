from typing import Optional, List, Callable, Any

from .vault_record import TypedRecord, TypedField


class TypedRecordFacade:
    def __init__(self) -> None:
        self._record: Optional[TypedRecord] = None

    def get_record(self):
        return self._record

    def set_record(self, record):
        if record is None or isinstance(record, TypedRecord):
            self._record = record
            self.load_typed_fields()
        else:
            raise ValueError('expected TypedRecord')

    def get_title(self):
        if isinstance(self._record, TypedRecord):
            return self._record.title
        raise ValueError('typed record is not assigned')

    def set_title(self, value):
        if isinstance(self._record, TypedRecord):
            self._record.title = value
        else:
            raise ValueError('typed record is not assigned')

    def get_notes(self):
        if isinstance(self._record, TypedRecord):
            return self._record.notes
        raise ValueError('typed record is not assigned')

    def set_notes(self, value):
        if isinstance(self._record, TypedRecord):
            self._record.notes = value
        else:
            raise ValueError('typed record is not assigned')

    record = property(fget=get_record, fset=set_record)
    title = property(fget=get_title, fset=set_title)
    notes = property(fget=get_notes, fset=set_notes)

    def load_typed_fields(self):
        pass


def string_list_getter(name: str) -> Callable[[TypedRecordFacade], List[str]]:
    def getter(obj):
        field = getattr(obj, name)
        if isinstance(field, TypedField):
            return field.value
    return getter


def string_getter(name: str) -> Callable[[TypedRecordFacade], str]:
    def getter(obj):
        field = getattr(obj, name)
        if isinstance(field, TypedField):
            return field.value[0] if len(field.value) > 0 else ''
    return getter


def string_setter(name: str) -> Callable[[Any, Any], None]:
    def setter(obj, value):
        field = getattr(obj, name)
        if isinstance(field, TypedField):
            if value:
                if len(field.value) > 0:
                    field.value[0] = value
                else:
                    field.value.append(value)
            else:
                field.value.clear()
    return setter


class FileRefRecordFacade(TypedRecordFacade):
    _file_ref_getter = string_list_getter('_file_ref')

    def __init__(self) -> None:
        super(FileRefRecordFacade, self).__init__()
        self._file_ref: Optional[TypedField]= None

    def load_typed_fields(self):
        if self.record:
            self._file_ref = next((x for x in self.record.fields if x.type == 'fileRef'), None)
            if self._file_ref is None:
                self._file_ref = TypedField.create_field('fileRef')
                self.record.fields.append(self._file_ref)
        else:
            self._file_ref = None
        super(FileRefRecordFacade, self).load_typed_fields()

    @property
    def file_ref(self):
        return FileRefRecordFacade._file_ref_getter(self)


class LoginRecordFacade(FileRefRecordFacade):
    _login_getter = string_getter('_login')
    _login_setter = string_setter('_login')
    _password_getter = string_getter('_password')
    _password_setter = string_setter('_password')
    _url_getter = string_getter('_url')
    _url_setter = string_setter('_url')
    _one_time_code_getter = string_getter('_oneTimeCode')
    _one_time_code_setter = string_setter('_oneTimeCode')

    def __init__(self) -> None:
        super(LoginRecordFacade, self).__init__()
        self._login: Optional[TypedField] = None
        self._password: Optional[TypedField] = None
        self._url: Optional[TypedField] = None
        self._one_time_code: Optional[TypedField] = None

    @property
    def login(self):
        return LoginRecordFacade._login_getter(self)

    @login.setter
    def login(self, value):
        LoginRecordFacade._login_setter(self, value)

    @property
    def password(self):
        return LoginRecordFacade._password_getter(self)

    @password.setter
    def password(self, value):
        LoginRecordFacade._password_setter(self, value)

    @property
    def url(self):
        return LoginRecordFacade._url_getter(self)

    @url.setter
    def url(self, value):
        LoginRecordFacade._url_setter(self, value)

    @property
    def one_time_code(self):
        return LoginRecordFacade._one_time_code_getter(self)

    @one_time_code.setter
    def one_time_code(self, value):
        LoginRecordFacade._one_time_code_setter(self, value)

    def load_typed_fields(self):
        if self.record:
            self.record.record_type = 'authentication'
            self._login = next((x for x in self.record.fields if x.type == 'authentication'), None)
            if self._login is None:
                self._login = TypedField.create_field('authentication')
                self.record.fields.append(self._login)
            self._password = next((x for x in self.record.fields if x.type == 'password'), None)
            if self._password is None:
                self._password = TypedField.create_field('password')
                self.record.fields.append(self._password)
            self._url = next((x for x in self.record.fields if x.type == 'url'), None)
            if self._url is None:
                self._url = TypedField.create_field('url')
                self.record.fields.append(self._url)
            self._one_time_code = next((x for x in self.record.fields if x.type == 'oneTimeCode'), None)
            if self._one_time_code is None:
                self._one_time_code = TypedField.create_field('oneTimeCode')
                self.record.fields.append(self._one_time_code)
        else:
            self._login = None
            self._password = None
            self._url = None
            self._one_time_code = None

        super(LoginRecordFacade, self).load_typed_fields()
