import enum
import logging
from typing import Optional, Type, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import libnacl
from xeddsa import XEdDSA25519

from .storage import Nothing, Storage


@enum.unique
class IdentityKeyPairVariation(enum.Enum):
    """
    The three variations of identity key pairs supported by :class:`IdentityKeyPair`.
    """

    CURVE25519 = 1
    ED25519_SEED = 2
    ED25519_SCALAR = 3


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

    This class can handle three variations of key pairs:

    * Curve25519 key pairs
    * Ed25519 key pairs, where a seed to derive the private scalar is the private key
    * Ed25519 key pairs, where the private scalar is the private key

    For all three variations, this type transparently handles the required conversions and caveats internally,
    to offer Ed25519-compatible signature creation and verification, as well as X25519-compatible
    Diffie-Hellman key agreement functionality.

    In case a new identity key pair needs to be generated, this implementation generates a seed-based Ed25519
    key pair.

    Note:
        This is the only actual cryptographic functionality offered by the core library. Everything else is
        backend-specific.
    """

    LOG_TAG = "omemo.core.identity_key_pair"

    def __init__(self) -> None:
        # Just the type definitions here
        self.__identity_key: XEdDSA25519

    @property
    def identity_key(self) -> bytes:
        """
        Returns:
            The public part of the identity key pair, in Ed25519 format.
        """

        return self.__identity_key.mont_pub_to_ed_pub(self.__identity_key.mont_pub)

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
            ikp_type = IdentityKeyPairVariation((await storage.load_primitive("/ikp/type", int)).from_just())
            logging.getLogger(IdentityKeyPair.LOG_TAG).debug(f"Type of stored ikp: {ikp_type}")
        except Nothing:
            logging.getLogger(IdentityKeyPair.LOG_TAG).info("Generating identity key pair.")
            # If there's no private key in storage, generate and store a new seed-based Ed25519 private key
            await storage.store_bytes("/ikp/key", Ed25519PrivateKey.generate().private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ))

            # Set and store the identity key pair type accordingly
            ikp_type = IdentityKeyPairVariation.ED25519_SEED
            await storage.store("/ikp/type", ikp_type.value)
            logging.getLogger(IdentityKeyPair.LOG_TAG).debug(
                "New seed-based Ed25519 identity key pair generated and stored."
            )

        key = (await storage.load_bytes("/ikp/key")).from_just()

        if ikp_type is IdentityKeyPairVariation.ED25519_SEED:
            # In case of a seed-based Ed25519 private key, generate and extract the private scalar
            logging.getLogger(IdentityKeyPair.LOG_TAG).debug("Extracting private scalar from Ed25519 seed.")
            key = libnacl.crypto_sign_ed25519_sk_to_curve25519(libnacl.crypto_sign_seed_keypair(key)[1])

        # Let XEdDSA handle the rest
        self.__identity_key = XEdDSA25519(key)

        logging.getLogger(IdentityKeyPair.LOG_TAG).debug("Identity key pair prepared.")

        return self

    def sign(self, message: bytes, nonce: Optional[bytes]) -> bytes:
        """
        Sign a message using this identity key pair.

        Args:
            message: The message to sign.
            nonce: The nonce to use while signing. If omitted or set to None, a nonce is generated.

        Returns:
            The signature of the message, not including the message itself.
        """

        return self.__identity_key.sign(message, nonce)

    @staticmethod
    def verify(message: bytes, signature: bytes, identity_key: bytes) -> bool:
        """
        Verify a signature.

        Args:
            message: The signed message.
            signature: The signature.
            identity_key: The identity key that allegedly signed the message.

        Returns:
            Whether the signature is valid.
        """

        try:
            Ed25519PublicKey.from_public_bytes(identity_key).verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def diffie_hellman(self, other_identity_key: bytes) -> bytes:
        """
        Perform Diffie-Hellman key agreement.

        Args:
            other_identity_key: The identity key of the other party.

        Returns:
            The shared secret.
        """

        assert self.__identity_key.mont_priv is not None
        return X25519PrivateKey.from_private_bytes(self.__identity_key.mont_priv).exchange(
            X25519PublicKey.from_public_bytes(libnacl.crypto_sign_ed25519_pk_to_curve25519(
                other_identity_key
            ))
        )


__all__ = [  # pylint: disable=unused-variable
    IdentityKeyPair.__name__
]
