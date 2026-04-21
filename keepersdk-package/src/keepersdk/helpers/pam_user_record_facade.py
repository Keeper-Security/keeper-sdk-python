from ..vault.record_facades import TypedRecordFacade, string_getter, string_setter, TypedField

def boolean_getter(name):
    def getter(obj):
        field = getattr(obj, name)
        if isinstance(field, TypedField):
            value = field.value[0] if len(field.value) > 0 else None
            if value is None:
                return None
            elif isinstance(value, bool) is True:
                return value

            if str(value).lower() in ['true', 'yes', '1', 'on']:
                return True
            elif str(value).lower() in ['false', 'no', '0', 'off']:
                return False
            return None
    return getter

def boolean_setter(name):
    def setter(obj, value):
        field = getattr(obj, name)
        if isinstance(field, TypedField):
            if value is not None:
                if isinstance(value, bool) is not True:
                    if str(value).lower() in ['true', 'yes', '1', 'on']:
                        value = True
                    elif str(value).lower() in ['false', 'no', '0', 'off']:
                        value = False
                if len(field.value) > 0:
                    field.value[0] = value
                else:
                    field.value.append(value)
            else:
                field.value.clear()
    return setter

class PamUserRecordFacade(TypedRecordFacade):
    _login_getter = string_getter('_login')
    _login_setter = string_setter('_login')
    _password_getter = string_getter('_password')
    _password_setter = string_setter('_password')
    _distinguishedName_getter = string_getter('_distinguishedName')
    _distinguishedName_setter = string_setter('_distinguishedName')
    _connectDatabase_getter = string_getter('_connectDatabase')
    _connectDatabase_setter = string_setter('_connectDatabase')
    _managed_getter = boolean_getter('_managed')
    _managed_setter = boolean_setter('_managed')
    _oneTimeCode_getter = string_getter('_oneTimeCode')
    _oneTimeCode_setter = string_setter('_oneTimeCode')

    def __init__(self):
        super(PamUserRecordFacade, self).__init__()
        self._login = None              
        self._password = None           
        self._distinguishedName = None  
        self._connectDatabase = None    
        self._managed = None            
        self._oneTimeCode = None        

    @property
    def login(self):
        return PamUserRecordFacade._login_getter(self)

    @login.setter
    def login(self, value):
        PamUserRecordFacade._login_setter(self, value)

    @property
    def password(self):
        return PamUserRecordFacade._password_getter(self)

    @password.setter
    def password(self, value):
        PamUserRecordFacade._password_setter(self, value)

    @property
    def distinguishedName(self):
        return PamUserRecordFacade._distinguishedName_getter(self)

    @distinguishedName.setter
    def distinguishedName(self, value):
        PamUserRecordFacade._distinguishedName_setter(self, value)

    @property
    def connectDatabase(self):
        return PamUserRecordFacade._connectDatabase_getter(self)

    @connectDatabase.setter
    def connectDatabase(self, value):
        PamUserRecordFacade._connectDatabase_setter(self, value)

    @property
    def managed(self):
        return PamUserRecordFacade._connectDatabase_getter(self)

    @managed.setter
    def managed(self, value):
        PamUserRecordFacade._managed_setter(self, value)

    @property
    def oneTimeCode(self):
        return PamUserRecordFacade._oneTimeCode_getter(self)

    @oneTimeCode.setter
    def oneTimeCode(self, value):
        PamUserRecordFacade._oneTimeCode_setter(self, value)

    def load_typed_fields(self):
        if self.record:
            self.record.type_name = 'pamUser'
            for attr in ["login", "password", "distinguishedName", "connectDatabase", "managed", "oneTimeCode"]:
                attr_prv = f"_{attr}"
                value = next((x for x in self.record.fields if x.type == attr), None)
                setattr(self, attr_prv, value)
                if value is None:
                    value = TypedField.create_field(field_type=attr, field_label='', required=False)
                    setattr(self, attr_prv, value)
                    self.record.fields.append(value)
        else:
            for attr in ["_login", "_password", "_distinguishedName", "_connectDatabase", "_managed", "_oneTimeCode"]:
                setattr(self, attr, None)
        super(PamUserRecordFacade, self).load_typed_fields()
