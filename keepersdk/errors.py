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


class KeeperError(Exception):
    def __init__(self, message):
        # type: (str) -> None
        self.message = message

    def __str__(self):
        return self.message


class KeeperApiError(KeeperError):
    def __init__(self, result_code, message):
        # type: (str, str) -> None
        KeeperError.__init__(self, message)
        self.result_code = result_code

    def __str__(self):
        return '({0}: {1})'.format(self.result_code, self.message)
