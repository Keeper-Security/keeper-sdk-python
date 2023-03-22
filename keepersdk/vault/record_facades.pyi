from typing import Optional, List

from vault import TypedRecord

class TypedRecordFacade:
    record: Optional[TypedRecord]
    title: Optional[str]
    notes: Optional[str]
    def load_typed_fields(self) -> None: ...


class FileRefRecordFacade(TypedRecordFacade):
    @property
    def file_ref(self) -> List[str]: ...

class LoginRecordFacade(FileRefRecordFacade):
    login: Optional[str]
    password: Optional[str]
    url: Optional[str]
    oneTimeCode: Optional[str]
