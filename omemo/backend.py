from abc import ABCMeta, abstractmethod
from typing import Any, Generic, Optional, Set, TypeVar

from .bundle import Bundle
from .identity_key_pair import IdentityKeyPair
from .message import Message
from .session import Session
from .types import DeviceInformation, OMEMOException

class BackendException(OMEMOException):
    pass

Plaintext = TypeVar("Plaintext")
class Backend(Generic[Plaintext], metaclass=ABCMeta):
    """
    TODO

    Note:
        Most methods can raise :class:`~omemo.storage.StorageException` in addition to those exceptions
        listed explicitly.
    
    Note:
        All parameters are treated as immutable unless explicitly noted otherwise.

    Note:
        All usages of "identity key" in the public API refer to the public part of the identity key pair in
        Ed25519 format. Otherwise, "identity key pair" is explicitly used to refer to the full key pair.

    TODO: Document the Plaintext generic
    """

    @property
    @abstractmethod
    def namespace() -> str:
        pass

    @abstractmethod
    async def load_session(self, device: DeviceInformation) -> Optional[Session]:
        """
        TODO
        """

        pass

    @abstractmethod
    async def build_session(self, device: DeviceInformation, bundle: Bundle) -> Session:
        """
        TODO
        """

        pass

    @abstractmethod
    async def encrypt_message(self, sessions: Set[Session], message: Plaintext) -> Message:
        """
        TODO
        """

        pass
    
    @abstractmethod
    async def signed_pre_key_age(self) -> int:
        """
        Returns:
            The age of the signed pre key, i.e. the time elapsed since it was last rotated, in seconds.
        """

        pass

    @abstractmethod
    async def rotate_signed_pre_key(self, identity_key_pair: IdentityKeyPair) -> Any:
        """
        Rotate the signed pre key. Keep the old signed pre key around for one additional rotation period, i.e.
        until this method is called again.

        Args:
            identity_key_pair: The identity key pair of this device, to sign the signed pre key with.

        Returns:
            Anything, the return value is ignored.
        """

        pass

    @abstractmethod
    async def bundle(self, bare_jid: str, device_id: int, identity_key: bytes) -> Bundle:
        """
        Args:
            bare_jid: The bare JID of this XMPP account, to be included in the bundle.
            device_id: The id of this device, to be included in the bundle.
            identity_key: The identity key assigned to this device, to be included in the bundle.

        Returns:
            The bundle containing public information about the cryptographic state of this backend.
        """

        pass

    @abstractmethod
    async def purge(self) -> Any:
        """
        Remove all data related to this backend from the storage.

        Returns:
            Anything, the return value is ignored.
        """

        pass
