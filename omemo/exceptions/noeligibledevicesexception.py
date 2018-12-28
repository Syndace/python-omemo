from .sessionmanagerexception import SessionManagerException

class NoEligibleDevicesException(SessionManagerException):
    def __init__(self, bare_jid):
        self.__bare_jid = bare_jid

    @property
    def bare_jid(self):
        return self.__bare_jid

    def __eq__(self, other):
        return (
            isinstance(other, NoEligibleDevicesException) and
            other.bare_jid == self.bare_jid
        )

    def __hash__(self):
        return hash(self.bare_jid)

    def __str__(self):
        return (
            "Encryption failed for every single device of {}. {} will not receive the "
            "message at all.".format(self.__bare_jid, self.__bare_jid)
        )
