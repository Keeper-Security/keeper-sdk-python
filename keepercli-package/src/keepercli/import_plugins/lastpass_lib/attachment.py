class LastpassAttachment:
    def __init__(self, file_id, parent_id, mimetype, storagekey, lastpass_size, encrypted_filename):
        super().__init__()
        self.file_id = file_id
        self.parent_id = parent_id
        self.mime = mimetype
        self.storagekey = storagekey
        self.lastpass_size = lastpass_size
        self.encrypted_filename = encrypted_filename
