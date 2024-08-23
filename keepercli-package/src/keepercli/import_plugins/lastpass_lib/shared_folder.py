class LastpassSharedFolder:
    def __init__(self, folder_id, name, members=None, teams=None):
        self.id = folder_id
        self.name = name
        self.members = members
        self.teams = teams
