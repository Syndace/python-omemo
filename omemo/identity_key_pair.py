import logging
import secrets
from typing import Optional, Type, TypeVar, Union

import xeddsa.bindings as xeddsa
from xeddsa.bindings import Ed25519Pub, Ed25519Signature, Priv, Seed, SharedSecret

from .storage import Nothing, Storage


IdentityKeyPairTypeT = TypeVar("IdentityKeyPairTypeT", bound="IdentityKeyPair")


class IdentityKeyPair:
    """
    The identity key pair associated to this device, shared by all backends.

    There are following requirements for the identity key pair:

    * It must be able to create and verify Ed25519-compatible signatures.
    * It must be able to perform X25519-compatible Diffie-Hellman key agreements.

    There are at least two different kinds of key pairs that can fulfill these requirements: Ed25519 key pairs
    and Curve25519 key pairs. The birational equivalence of both curves can be used to "convert" one pair to
    the other, with caveats.

    For all possible variations, this type transparently handles the required conversions and caveats
    internally, to offer Ed25519-compatible signature creation and verification, as well as X25519-compatible
    Diffie-Hellman key agreement functionality.

    Note:
        This is the only actual cryptographic functionality offered by the core library. Everything else is
        backend-specific.

    TODO: Hmm. Maybe more of an API to request the identity key pair in a specific format, rather than provide
          signing/x25519?
    """

    LOG_TAG = "omemo.core.identity_key_pair"

    def __init__(self) -> None:
        # Just the type definitions here
        self.__key: Union[Priv, Seed]
        self.__is_seed: bool

    @property
    def identity_key(self) -> Ed25519Pub:
        """
        Returns:
            The public part of the identity key pair, in Ed25519 format.
        """

        if self.__is_seed:
            return xeddsa.seed_to_ed25519_pub(self.__key)
        else:
            return xeddsa.priv_to_ed25519_pub(self.__key)

    @classmethod
    async def get(cls: Type[IdentityKeyPairTypeT], storage: Storage) -> IdentityKeyPairTypeT:
        """
        Get the identity key pair.

        Args:
            storage: The storage for all OMEMO-related data.

        Returns:
            The identity key pair, which has either been loaded from storage or newly generated.

        Note:
            There is only one identity key pair. All instances of this class refer to the same storage
            locations, thus the same data.
        """

        logging.getLogger(IdentityKeyPair.LOG_TAG).debug(f"Creating instance from storage {storage}.")

        self = cls()

        try:
            self.__is_seed = (await storage.load_primitive("/ik/is_seed", bool)).from_just()
            logging.getLogger(IdentityKeyPair.LOG_TAG).debug(
                f"Loaded identity key from storage. is_seed={self.__is_seed}"
            )
        except Nothing:
            logging.getLogger(IdentityKeyPair.LOG_TAG).info("Generating identity key.")

            # If there's no private key in storage, generate and store a new seed
            self.__is_seed = True
            await storage.store("/ik/is_seed", True)
            await storage.store_bytes("/ik/key", secrets.token_bytes(32))

            logging.getLogger(IdentityKeyPair.LOG_TAG).debug("New seed generated and stored.")

        self.__key = (await storage.load_bytes("/ik/key")).from_just()

        logging.getLogger(IdentityKeyPair.LOG_TAG).debug("Identity key prepared.")

        return self

    def sign(self, message: bytes, enforce_ed25519_pub_sign: Optional[bool] = None) -> Ed25519Signature:
        """
        Sign a message using this identity key pair.

        Args:
            message: The message to sign.
            enforce_ed25519_pub_sign: Used if the Ed25519 public key needs a specific sign enforced. Pass
                `None` if the sign does not need to be enforced, `True` if the sign bit needs to be set and
                `False` if it needs not be set. For example, XEdDSA needs the sign bit to not be set.

        Returns:
            The signature of the message, not including the message itself.
        """

        if enforce_ed25519_pub_sign is None:
            if self.__is_seed:
                return xeddsa.ed25519_seed_sign(self.__key, message)
            else:
                return xeddsa.ed25519_priv_sign(self.__key, message)
        else:
            return xeddsa.ed25519_priv_sign(xeddsa.priv_force_sign(
                xeddsa.seed_to_priv(self.__key) if self.__is_seed else self.__key,
                enforce_ed25519_pub_sign
            ) , message)

    @staticmethod
    def verify(message: bytes, signature: Ed25519Signature, identity_key: Ed25519Pub) -> bool:
        """
        Verify a signature.

        Args:
            message: The signed message.
            signature: The signature.
            identity_key: The identity key that allegedly signed the message.

        Returns:
            Whether the signature verification was successful.
        """

        return xeddsa.ed25519_verify(signature, identity_key, message)

    def diffie_hellman(self, other_identity_key: Ed25519Pub) -> SharedSecret:
        """
        Perform Diffie-Hellman key agreement.

        Args:
            other_identity_key: The identity key of the other party.

        Returns:
            The shared secret.
        """

        return xeddsa.x25519(
            xeddsa.seed_to_priv(self.__key) if self.__is_seed else self.__key,
            xeddsa.ed25519_pub_to_curve25519_pub(other_identity_key)
        )


__all__ = [  # pylint: disable=unused-variable
    IdentityKeyPair.__name__
]
