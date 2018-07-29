import x3dh

from . import default
from .exceptions import UnknownKeyException
from .extendedpublicbundle import ExtendedPublicBundle

class State(x3dh.State):
    def __init__(self, configuration = None):
        if configuration == None:
            configuration = default.x3dh.Config()

        super(State, self).__init__(configuration, default.x3dh.EncryptionKeyEncoder)

        self.__spk_id  = 0
        self.__spk_enc = None

        self.__otpk_id_counter = 0
        self.__otpk_ids = {}

    def getPublicBundle(self):
        """
        The current signal OMEMO standard works with ids instead of sending full
        public keys whenever possible, probably to reduce traffic.
        This is not part of the core specification though, so it has to be added here.
        It is added in the getPublicBundle method, because this method is the only way to
        get public data and is the perfect spot to update ids.
        """

        bundle = super(State, self).getPublicBundle()

        self.__updateIDs()

        return self.__extendBundle(bundle)

    def __updateIDs(self):
        # Check, whether the spk has changed and assign it the next id in that case
        if self.spk.enc != self.__spk_enc:
            self.__spk_enc = self.spk.enc
            self.__spk_id += 1

        otpks        = [ otpk.enc for otpk in self.otpks ]
        hidden_otpks = [ otpk.enc for otpk in self.hidden_otpks ]

        # Synchronize the list of OTPKs.
        # First, remove all entries in the current dict,
        # that were removed from the official list.
        for otpk in list(self.__otpk_ids):
            if not (otpk in otpks or otpk in hidden_otpks):
                del self.__otpk_ids[otpk]

        # Second, add new OTPKs to the dict and assign them ids
        for otpk in otpks:
            if not otpk in self.__otpk_ids:
                self.__otpk_id_counter += 1
                self.__otpk_ids[otpk] = self.__otpk_id_counter

    def __extendBundle(self, bundle):
        """
        Extend the bundle, adding the ids of the respective keys to all entries.
        """

        ik = bundle.ik

        spk = {
            "key": bundle.spk,
            "id": self.getSPKID(bundle.spk)
        }

        spk_signature = bundle.spk_signature

        otpks = [ {
            "key": otpk,
            "id": self.getOTPKID(otpk)
        } for otpk in bundle.otpks ]

        return ExtendedPublicBundle(ik, spk, spk_signature, otpks)

    def __reduceBundle(self, bundle):
        """
        Reduce the bundle, removing all ids of the respective keys from all entries.
        """

        ik = bundle.ik

        spk = bundle.spk["key"]

        spk_signature = bundle.spk_signature

        otpks = [ otpk["key"] for otpk in bundle.otpks ]

        return x3dh.PublicBundle(ik, spk, spk_signature, otpks)

    def getSPKID(self, spk):
        self.__updateIDs()

        # If the requested spk is the most recent one...
        if self.__spk_enc == spk:
            # ...return the id
            return self.__spk_id

        raise UnknownKeyException("Tried to get the id of an unknown SPK.")

    def getSPK(self, spk_id):
        self.__updateIDs()

        # If the requested spk id is the one contained in this bundle...
        if self.__spk_id == spk_id:
            # ...return the key
            return self.__spk_enc

        raise UnknownKeyException("Tried to get the SPK for an unknown id.")

    def getOTPKID(self, otpk):
        self.__updateIDs()

        otpk_id = self.__otpk_ids.get(otpk)

        if otpk_id == None:
            raise UnknownKeyException("Tried to get the id of an unknown OTPK.")

        return otpk_id

    def getOTPK(self, otpk_id):
        self.__updateIDs()

        otpks = [ x[0] for x in self.__otpk_ids.items() if x[1] == otpk_id ]

        if len(otpks) != 1:
            raise UnknownKeyException("Tried to get the OTPK for an unknown id.")

        return otpks[0]

    def initSessionActive(self, other_public_bundle, *args, **kwargs):
        other_public_bundle = self.__reduceBundle(other_public_bundle)

        return super(State, self).initSessionActive(other_public_bundle, *args, **kwargs)
