from __future__ import absolute_import

from .encryptionkeyencoder import EncryptionKeyEncoder

import x3dh

class State(x3dh.State):
    def __init__(self):
        """
        Sets the constructor parameters to the defaults used by OMEMO.
        The curve, min_num_otpks and max_num_otpks parameters were found in the XEP
        (https://xmpp.org/extensions/xep-0384.html).

        The hash_function and info_string parameters were found in the source code of
        libsignal-protocol-java
        (https://github.com/WhisperSystems/libsignal-protocol-java).

        The timeout for the SPK is defaulted to one week.
        """

        return super(State, self).__init__(
            "WhisperText",       # info_string
            "25519",             # curve
            "SHA-256",           # hash_function
            7 * 24 * 60 * 60,    # spk_timeout
            20,                  # min_num_otpks
            100,                 # max_num_otpks
            EncryptionKeyEncoder # encryption_key_encoder_class
        )

    def serialize(self):
        return {
            "super": super(State, self).serialize()
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        return super(State, cls).fromSerialized(
            serialized["super"],
            *args,
            **kwargs
        )
