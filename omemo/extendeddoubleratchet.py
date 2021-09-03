import base64

def make(backend):
    class ExtendedDoubleRatchet(backend.DoubleRatchet):
        def __init__(self, other_ik, *args, **kwargs):
            super().__init__(*args, **kwargs)

            self.__other_ik = other_ik

        def serialize(self):
            return {
                "super"    : super().serialize(),
                "other_ik" : base64.b64encode(self.__other_ik).decode("US-ASCII")
            }

        @classmethod
        def fromSerialized(cls, serialized, *args, **kwargs):
            self = super().fromSerialized(
                serialized["super"],
                *args,
                ad = None, # TODO: This is ugly
                root_key = None,
                **kwargs
            )

            self.__other_ik = base64.b64decode(serialized["other_ik"].encode("US-ASCII"))

            return self

        @property
        def ik(self):
            return self.__other_ik

        @property
        def receiving_chain_length(self):
            return self._DoubleRatchet__skr.receiving_chain_length

    return ExtendedDoubleRatchet
