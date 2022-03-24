import enum
from typing import Optional, Type, TypeVar

from .storage import Nothing, Storage

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import libnacl
from xeddsa import XEdDSA25519

@enum.unique
class IdentityKeyPairVariation(enum.Enum):
    """
    The three variations of identity key pairs supported by :class:`IdentityKeyPair`.
    """

    Curve25519    = 1
    Ed25519Seed   = 2
    Ed25519Scalar = 3

IdentityKeyPairType = TypeVar("IdentityKeyPairType", bound="IdentityKeyPair")
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
    async def get(cls: Type[IdentityKeyPairType], storage: Storage) -> IdentityKeyPairType:
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

        self = cls()

        try:
            ikp_type = IdentityKeyPairVariation((await storage.load_primitive("/ikp/type", int)).from_just())
        except Nothing:
            # If there's no private key in storage, generate and store a new seed-based Ed25519 private key
            await storage.store_bytes("/ikp/key", Ed25519PrivateKey.generate().private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ))

            # Set and store the identity key pair type accordingly
            ikp_type = IdentityKeyPairVariation.Ed25519Seed
            await storage.store("/ikp/type", ikp_type.value)

        key = (await storage.load_bytes("/ikp/key")).from_just()

        if ikp_type is IdentityKeyPairVariation.Ed25519Seed:
            # In case of a seed-based Ed25519 private key, generate and extract the private scalar
            key = libnacl.crypto_sign_seed_keypair(key)[1]
            # TODO: https://github.com/Syndace/python-x3dh/blob/stable/x3dh/state.py#L593 is probably broken

        # Let XEdDSA handle the rest
        self.__identity_key = XEdDSA25519(key)

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
        assert self.__identity_key.mont_priv is not None
        return X25519PrivateKey.from_private_bytes(self.__identity_key.mont_priv).exchange(
            X25519PublicKey.from_public_bytes(libnacl.crypto_sign_ed25519_pk_to_curve25519(
                other_identity_key
            ))
        )
