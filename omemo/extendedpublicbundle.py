import binascii

from . import default
from .exceptions import UnknownKeyException

class ExtendedPublicBundle(object):
    """
    This class looks exactly the same as the PublicBundle class,
    but the types of the fields are a bit different:

    The spk field is not a key, but a dictionary containing the key and the id:
    spk = {
        "key": key,
        "id": id
    }

    The otpks field is not an array of keys, but an array of dictionaries
    containing the key and the id:
    otpks = [
        {
            "key": key,
            "id": id
        },
        {
            "key": key,
            "id": id
        },
        ...
    ]
    """

    def __init__(self, ik, spk, spk_signature, otpks):
        self.__ik = ik
        self.__spk = spk
        self.__spk_signature = spk_signature
        self.__otpks = otpks

    @property
    def ik(self):
        return self.__ik

    @property
    def spk(self):
        return self.__spk

    @property
    def spk_signature(self):
        return self.__spk_signature

    @property
    def otpks(self):
        return self.__otpks

    @property
    def fingerprint(self):
        return binascii.hexlify(default.wireformat.encodePublicKey(self.__ik)).decode("ASCII")

    def findOTPKId(self, otpk):
        otpks = list(filter(lambda x: x["key"] == otpk, self.otpks))

        if len(otpks) != 1:
            raise UnknownKeyException("Tried to get the id of an unknown OTPK.")

        return otpks[0]["id"]

    def findSPKId(self, spk):
        # If the requested spk is the one contained in this bundle...
        if self.spk["key"] == spk:
            # ...return the id
            return self.spk["id"]

        raise UnknownKeyException("Tried to get the id of an unknown SPK.")
