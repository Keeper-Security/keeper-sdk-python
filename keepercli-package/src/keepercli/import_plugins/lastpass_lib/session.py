# coding: utf-8
class Session(object):
    def __init__(self, session_id, key_iteration_count):
        self.id = session_id
        self.key_iteration_count = key_iteration_count

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Session):
            return self.id == other.id and self.key_iteration_count == other.key_iteration_count
        return False
