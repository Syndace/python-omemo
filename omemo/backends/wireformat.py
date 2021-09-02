class WireFormat:
    @staticmethod
    def messageFromWire(obj):
        raise NotImplementedError

    @staticmethod
    def finalizeMessageFromWire(obj, additional):
        raise NotImplementedError

    @staticmethod
    def messageToWire(ciphertext, header, additional):
        raise NotImplementedError

    @staticmethod
    def preKeyMessageFromWire(obj):
        raise NotImplementedError

    @staticmethod
    def finalizePreKeyMessageFromWire(obj, additional):
        raise NotImplementedError

    @staticmethod
    def preKeyMessageToWire(session_init_data, message, additional):
        raise NotImplementedError
