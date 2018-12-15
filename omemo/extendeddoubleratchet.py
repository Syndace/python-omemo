from __future__ import absolute_import

import base64

def make(backend):
    class ExtendedDoubleRatchet(backend.DoubleRatchet):
        def __init__(self, other_ik, *args, **kwargs):
            super(ExtendedDoubleRatchet, self).__init__(*args, **kwargs)

            self.__other_ik = other_ik

        def serialize(self):
            return {
                "super"    : super(ExtendedDoubleRatchet, self).serialize(),
                "other_ik" : base64.b64encode(self.__other_ik).decode("US-ASCII")
            }

        @classmethod
        def fromSerialized(cls, serialized, *args, **kwargs):
            self = super(ExtendedDoubleRatchet, cls).fromSerialized(
                serialized["super"],
                *args,
                **kwargs
            )

            self.__other_ik = base64.b64decode(serialized["other_ik"].encode("US-ASCII"))

            return self

        @property
        def ik(self):
            return self.__other_ik

    return ExtendedDoubleRatchet
