import copy

from .exceptions import UnknownKeyException

class ExtendedPublicBundle:
    """
    This class looks exactly the same as the PublicBundle class, but the types of the
    fields are a bit different:

    The spk field is not a key, but a dictionary containing the key and the id:
    spk = {
        "key" : key,
        "id"  : id
    }

    The otpks field is not an array of keys, but an array of dictionaries containing the
    key and the id:
    otpks = [
        {
            "key" : key,
            "id"  : id
        },
        {
            "key" : key,
            "id"  : id
        },
        ...
    ]
    """

    def __init__(self, ik, spk, spk_signature, otpks):
        self.__ik = ik
        self.__spk = copy.deepcopy(spk)
        self.__spk_signature = spk_signature
        self.__otpks = copy.deepcopy(otpks)

    @classmethod
    def parse(cls, backend, ik, spk, spk_signature, otpks):
        """
        Use this method when creating a bundle from data you retrieved directly from some
        PEP node. This method applies an additional decoding step to the public keys in
        the bundle. Pass the same structure as the constructor expects.
        """

        ik = backend.decodePublicKey(ik)[0]

        spk = {
            "key" : backend.decodePublicKey(spk["key"])[0],
            "id"  : spk["id"]
        }

        otpks = list(map(lambda otpk: {
            "key" : backend.decodePublicKey(otpk["key"])[0],
            "id"  : otpk["id"]
        }, otpks))

        return cls(ik, spk, spk_signature, otpks)

    def serialize(self, backend):
        """
        Use this method to prepare the data to be uploaded directly to some PEP node. This
        method applies an additional encoding step to the public keys in the bundle. The
        result is a dictionary with the keys ik, spk, spk_signature and otpks. The values
        are structured the same way as the inputs of the constructor.
        """

        return {
            "ik": backend.encodePublicKey(self.ik, "25519"),
            "spk": {
                "id"  : self.spk["id"],
                "key" : backend.encodePublicKey(self.spk["key"], "25519"),
            },
            "spk_signature": self.spk_signature,
            "otpks": list(map(lambda otpk: {
                "id"  : otpk["id"],
                "key" : backend.encodePublicKey(otpk["key"], "25519")
            }, self.otpks))
        }

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

    def __eq__(self, other):
        try:
            return (
                self.ik == other.ik and
                self.spk == other.spk and
                self.spk_signature == other.spk_signature and
                self.otpks == other.otpks
            )
        except:
            return False
