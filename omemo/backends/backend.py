class Backend:
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

    def encodePublicKey(self, *args, **kwargs):
        return self.__X3DHPKEncoder.encodePublicKey(*args, **kwargs)

    def decodePublicKey(self, *args, **kwargs):
        return self.__X3DHPKEncoder.decodePublicKey(*args, **kwargs)

    @property
    def DoubleRatchet(self):
        return self.__DoubleRatchet
