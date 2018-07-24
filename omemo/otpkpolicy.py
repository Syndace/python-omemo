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

            # A boolean indicating whether this message was retrieved from
            # some sort of storage, e.g. MAM
            "from_storage": bool,

            # A list of UNIX timestamps, for each Message that answered this PreKeyMessage
            "anwers": list<int>
        }
        """

        raise NotImplementedError
