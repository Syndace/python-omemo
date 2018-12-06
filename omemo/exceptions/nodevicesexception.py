class NoDevicesException(Exception):
    def __init__(self, bare_jid):
        self.__bare_jid = bare_jid

    @property
    def bare_jid(self):
        return self.__bare_jid

    def __eq__(self, other):
        return isinstance(other, NoDevicesException) and other.bare_jid == self.bare_jid

    def __hash__(self):
        return hash(self.bare_jid)
