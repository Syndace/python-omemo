import x3dh

class X3DHPKEncoder(x3dh.PublicKeyEncoder):
    @staticmethod
    def encodePublicKey(key, key_type):
        """
        Encode given (Montgomery) public key and the type of the key into a sequence of
        bytes.

        :param key: The public key to encode, as a bytes-like object.
        :param key_type: Identification of the curve that this key is used with.
            Currently the only allowed value is (the string) "25519".
        :returns: A bytes-like object, which encodes the public key and possibly its type.
        """

        raise NotImplementedError

    @staticmethod
    def decodePublicKey(key_encoded):
        """
        Decode given (Montgomery) public key and the type of the key from a sequence of
        bytes.

        :param key_encoded: The public key and the type of the key to decode, as a
            bytes-like object.
        :returns: A tuple consisting of a bytes-like object encoding the public key and a
            string identifying the type of the curve this key is used with. Currently the
            only allowed value is (the string) "25519".
        """

        raise NotImplementedError
