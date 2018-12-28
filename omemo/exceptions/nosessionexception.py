from .sessionmanagerexception import SessionManagerException

class NoSessionException(SessionManagerException):
    def __init__(self, bare_jid, device):
        self.__bare_jid = bare_jid
        self.__device   = device

    @property
    def bare_jid(self):
        return self.__bare_jid

    @property
    def device(self):
        return self.__device

    def __eq__(self, other):
        return (
            isinstance(other, NoSessionException) and
            other.bare_jid == self.bare_jid and
            other.device == self.device
        )

    def __hash__(self):
        return hash((self.bare_jid, self.device))

    def __str__(self):
        return (
            "Tried to decrypt a message from {} on device {}, but there is no session "
            "with that device.".format(self.__bare_jid, self.__device)
        )
