class Chunk(object):
    def __init__(self, chunk_id, payload):
        self.id = chunk_id
        self.payload = payload

    def __eq__(self, other):
        return self.id == other.id and self.payload == other.payload
