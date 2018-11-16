class Backend(object):
    def __init__(self, WireFormat, X3DHState, DoubleRatchet):
        self.__WireFormat    = WireFormat
        self.__X3DHState     = X3DHState
        self.__DoubleRatchet = DoubleRatchet

    @property
    def WireFormat(self):
        return self.__WireFormat

    @property
    def X3DHState(self):
        return self.__X3DHState

    @property
    def DoubleRatchet(self):
        return self.__DoubleRatchet
