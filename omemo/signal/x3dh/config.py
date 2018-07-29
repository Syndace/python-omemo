import x3dh

class Config(x3dh.Config):
    def __init__(
        self,
        info_string = "WhisperText",
        curve = "25519",
        hash_function = "SHA-256",
        spk_timeout = 7 * 24 * 60 * 60,
        min_num_otpks = 20,
        max_num_otpks = 100
    ):
        """
        Sets the constructor parameters to the defaults used by OMEMO.
        The curve, min_num_otpks and max_num_otpks parameters were found in the XEP
        (https://xmpp.org/extensions/xep-0384.html).

        The hash_function and info_string parameters were found in the source code of
        libsignal-protocol-java
        (https://github.com/WhisperSystems/libsignal-protocol-java).

        The timeout for the SPK is defaulted to one week.
        """

        return super(Config, self).__init__(
            info_string,
            curve,
            hash_function,
            spk_timeout,
            min_num_otpks,
            max_num_otpks
        )
