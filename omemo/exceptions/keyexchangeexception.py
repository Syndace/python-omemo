class KeyExchangeException(Exception):
    def __init__(self, bare_jid, device, message):
        super(KeyExchangeException, self).__init__(message)

        self.__bare_jid = bare_jid
        self.__device = device

    @property
    def bare_jid(self):
        return self.__bare_jid

    @property
    def device(self):
        return self.__device

    def __eq__(self, other):
        return (
            isinstance(other, KeyExchangeException) and
            other.bare_jid == self.bare_jid and
            other.device == self.device
        )

    def __hash__(self):
        return hash((self.bare_jid, self.device))
