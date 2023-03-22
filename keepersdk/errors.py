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


class KeeperError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class AuthFailedError(KeeperError):
    pass


class KeeperApiError(KeeperError):
    def __init__(self, result_code, message):
        super(KeeperApiError, self).__init__(message)
        self.result_code = result_code

    def __str__(self):
        return f'Keeper API: ({self.result_code}: {self.message})'


class RegionRedirectError(KeeperError):
    def __init__(self, region_host, message):  # type: (str, str) -> None
        super(RegionRedirectError, self).__init__(message)
        self.region_host = region_host

    def __str__(self):
        return f'Region redirect: {self.region_host}'


class InvalidDeviceTokenError(KeeperError):
    pass
