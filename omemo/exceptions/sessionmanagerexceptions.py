class SessionManagerException(Exception):
    pass

class NoDevicesException(SessionManagerException):
    pass

class UntrustedException(SessionManagerException):
    pass

class MissingBundleException(SessionManagerException):
    pass

class NoTrustedDevicesException(SessionManagerException):
    pass
