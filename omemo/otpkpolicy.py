class OTPKPolicy(object):
    @staticmethod
    def decideOTPK(preKeyMessages):
        """
        Use the data passed to this method to decide, whether to keep an OTPK or not.
        Return True to keep the OTPK and False to delete it.

        The preKeyMessages parameter is a list of dictionaries, each element looking like this:
        {
            "timestamp":    int,      # The UNIX timestamp that PreKeyMessage was received on
            "from_storage": bool,     # A boolean indicating whether this message was retrieved from some sort of storage, e.g. MAM
            "anwers":       list<int> # A list of UNIX timestamps, for each Message that was answered to this PreKeyMessage
        }
        """

        raise NotImplementedError
