class Backend(object):
    def __init__(self, WireFormat, X3DHState, X3DHPKEncoder, DoubleRatchet):
        self.__WireFormat    = WireFormat
        self.__X3DHState     = X3DHState
        self.__X3DHPKEncoder = X3DHPKEncoder
        self.__DoubleRatchet = DoubleRatchet

    @property
    def WireFormat(self):
        return self.__WireFormat

    @property
    def X3DHState(self):
        return self.__X3DHState

    def encodePublicKey(self, public_key):
        return self.__X3DHPKEncoder.encodePublicKey(public_key)

    def decodePublicKey(self, public_key_encoded):
        return self.__X3DHPKEncoder.decodePublicKey(public_key_encoded)

    @property
    def DoubleRatchet(self):
        return self.__DoubleRatchet
