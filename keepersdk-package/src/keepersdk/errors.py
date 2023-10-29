class KeeperError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message

    def __str__(self):
        return self.message


class KeeperApiError(KeeperError):
    def __init__(self, result_code: str, message: str) -> None:
        super(KeeperApiError, self).__init__(message)
        self.result_code = result_code

    def __str__(self):
        return f'Keeper API: ({self.result_code}: {self.message})'


class RegionRedirectError(KeeperError):
    def __init__(self, region_host: str, message: str) -> None:
        super(RegionRedirectError, self).__init__(message)
        self.region_host = region_host

    def __str__(self):
        return f'Region redirect: {self.region_host}'


class InvalidDeviceTokenError(KeeperError):
    pass
