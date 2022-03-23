from typing import Type, TypeVar

from .storage import Storage

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

    @property
    def identity_key(self) -> bytes:
        """
        Returns:
            The public part of the identity key pair, in Ed25519 format.
        """

        # TODO

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

        # TODO

    def sign(self, message: bytes) -> bytes:
        """
        TODO
        """

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        TODO
        """

    # TODO: X25519 functionality
