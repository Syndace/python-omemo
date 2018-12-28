from .sessionmanagerexception import SessionManagerException

class UntrustedException(SessionManagerException):
    def __init__(self, bare_jid, device, ik):
        self.__bare_jid = bare_jid
        self.__device   = device
        self.__ik       = ik

    @property
    def bare_jid(self):
        return self.__bare_jid

    @property
    def device(self):
        return self.__device

    @property
    def ik(self):
        return self.__ik

    def __eq__(self, other):
        return (
            isinstance(other, UntrustedException) and
            other.bare_jid == self.bare_jid and
            other.device == self.device and
            other.ik == self.ik
        )

    def __hash__(self):
        return hash((self.bare_jid, self.device, self.ik))

    def __str__(self):
        return (
            "The key {} of {} on device {} is untrusted."
            .format(self.__ik, self.__bare_jid, self.__device)
        )
