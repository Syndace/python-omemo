from .sessionmanagerexception import SessionManagerException

class TrustException(SessionManagerException):
    def __init__(self, bare_jid, device, ik, problem):
        # problem can be either (the string) "untrusted" or "undecided"
        self.__bare_jid = bare_jid
        self.__device   = device
        self.__ik       = ik
        self.__problem  = problem

    @property
    def bare_jid(self):
        return self.__bare_jid

    @property
    def device(self):
        return self.__device

    @property
    def ik(self):
        return self.__ik

    @property
    def problem(self):
        return self.__problem

    def __eq__(self, other):
        return (
            isinstance(other, TrustException) and
            other.bare_jid == self.bare_jid and
            other.device   == self.device and
            other.ik       == self.ik and
            other.problem  == self.problem
        )

    def __hash__(self):
        return hash((self.bare_jid, self.device, self.ik, self.problem))

    def __str__(self):
        return (
            "The key {} of {} on device {} is {}."
            .format(self.__ik, self.__bare_jid, self.__device, self.__problem)
        )
