class OTPKPolicy(object):
    @staticmethod
    def decideOTPK(preKeyMessages):
        """
        Use the data passed to this method to decide, whether to keep an OTPK or not.
        Return True to keep the OTPK and False to delete it.

        The preKeyMessages parameter is a list of dictionaries with following structure:
        {
            # The UNIX timestamp that PreKeyMessage was received on
            "timestamp": int,

            # A list of UNIX timestamps, for each Message that answered this PreKeyMessage
            "answers": list<int>,

            # This key can be used by implementations to store any sort of additional
            # information about the message, which can be used for more complex logic to
            # decide whether to keep the one-time pre key. One example that would make a
            # lot of sense is a flag, which indicates whether the message was retrieved
            # from some storage mechanism like mam. Messages retrieved from mam should
            # probably not trigger one-time pre key deletion, because there might be more
            # pre key messages waiting in the mam catch-up that use the same one-time pre
            # key.
            # The value of this key must consist of Python primitives like ints, floats,
            # strings, booleans, lists, dictionaries or None (basically everything
            # json-serializable).
            "additional_information": any
        }
        """

        raise NotImplementedError
