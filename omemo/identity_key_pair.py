from abc import ABC, abstractmethod
import logging
import secrets

import xeddsa.bindings as xeddsa
from xeddsa.bindings import Ed25519Pub, Priv, Seed

from .storage import NothingException, Storage


class IdentityKeyPair(ABC):
    """
    The identity key pair associated to this device, shared by all backends.

    There are following requirements for the identity key pair:

    * It must be able to create and verify Ed25519-compatible signatures.
    * It must be able to perform X25519-compatible Diffie-Hellman key agreements.

    There are at least two different kinds of key pairs that can fulfill these requirements: Ed25519 key pairs
    and Curve25519 key pairs. The birational equivalence of both curves can be used to "convert" one pair to
    the other.

    Both types of key pairs share the same private key, however instead of a private key, a seed can be used
    which the private key is derived from using SHA-512. This is standard practice for Ed25519, where the
    other 32 bytes of the SHA-512 seed hash are used as a nonce during signing. If a new key pair has to be
    generated, this implementation generates a seed.

    Note:
        This is the only actual cryptographic functionality offered by the core library. Everything else is
        backend-specific.
    """

    LOG_TAG = "omemo.core.identity_key_pair"

    @staticmethod
    async def get(storage: Storage) -> "IdentityKeyPair":
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

        is_seed: bool
        key: bytes
        try:
            # Try to load both is_seed and the key. If any one of the loads fails, generate a new seed.
            is_seed = (await storage.load_primitive("/ikp/is_seed", bool)).from_just()
            key = (await storage.load_bytes("/ikp/key")).from_just()

            logging.getLogger(IdentityKeyPair.LOG_TAG).debug(
                f"Loaded identity key from storage. is_seed={is_seed}"
            )
        except NothingException:
            # If there's no private key in storage, generate and store a new seed
            logging.getLogger(IdentityKeyPair.LOG_TAG).info("Generating identity key.")

            is_seed = True
            key = secrets.token_bytes(32)

            await storage.store("/ikp/is_seed", is_seed)
            await storage.store_bytes("/ikp/key", key)

            logging.getLogger(IdentityKeyPair.LOG_TAG).debug("New seed generated and stored.")

        logging.getLogger(IdentityKeyPair.LOG_TAG).debug("Identity key prepared.")

        return IdentityKeyPairSeed(key) if is_seed else IdentityKeyPairPriv(key)

    @property
    @abstractmethod
    def is_seed(self) -> bool:
        """
        Returns:
            Whether this is a :class:`IdentityKeyPairSeed`.
        """

    @property
    @abstractmethod
    def is_priv(self) -> bool:
        """
        Returns:
            Whether this is a :class:`IdentityKeyPairPriv`.
        """

    @abstractmethod
    def as_priv(self) -> "IdentityKeyPairPriv":
        """
        Returns:
            An :class:`IdentityKeyPairPriv` derived from this instance (if necessary).
        """

    @property
    @abstractmethod
    def identity_key(self) -> Ed25519Pub:
        """
        Returns:
            The public part of this identity key pair, in Ed25519 format.
        """


class IdentityKeyPairSeed(IdentityKeyPair):
    """
    An :class:`IdentityKeyPair` represented by a seed.
    """

    def __init__(self, seed: Seed) -> None:
        self.__seed = seed

    @property
    def is_seed(self) -> bool:
        return True

    @property
    def is_priv(self) -> bool:
        return False

    def as_priv(self) -> "IdentityKeyPairPriv":
        return IdentityKeyPairPriv(xeddsa.seed_to_priv(self.__seed))

    @property
    def identity_key(self) -> Ed25519Pub:
        return xeddsa.seed_to_ed25519_pub(self.__seed)

    @property
    def seed(self) -> Seed:
        """
        Returns:
            The Curve25519/Ed25519 seed.
        """

        return self.__seed


class IdentityKeyPairPriv(IdentityKeyPair):
    """
    An :class:`IdentityKeyPair` represented by a private key.
    """

    def __init__(self, priv: Priv) -> None:
        self.__priv = priv

    @property
    def is_seed(self) -> bool:
        return False

    @property
    def is_priv(self) -> bool:
        return True

    def as_priv(self) -> "IdentityKeyPairPriv":
        return self

    @property
    def identity_key(self) -> Ed25519Pub:
        return xeddsa.priv_to_ed25519_pub(self.__priv)

    @property
    def priv(self) -> Priv:
        """
        Returns:
            The Curve25519/Ed25519 private key.
        """

        return self.__priv


__all__ = [  # pylint: disable=unused-variable
    IdentityKeyPair.__name__,
    IdentityKeyPairSeed.__name__,
    IdentityKeyPairPriv.__name__
]
