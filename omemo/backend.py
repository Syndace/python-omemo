from abc import ABCMeta, abstractmethod
from typing import Any, Generic, Optional, Set, TypeVar

from .bundle import Bundle
from .identity_key_pair import IdentityKeyPair
from .message import Encrypted, KeyExchange, Message
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
    
    Warning:
        All parameters must be treated as immutable unless explicitly noted otherwise.

    Note:
        All usages of "identity key" in the public API refer to the public part of the identity key pair in
        Ed25519 format. Otherwise, "identity key pair" is explicitly used to refer to the full key pair.

    TODO: Document the Plaintext generic
    """

    @property
    @abstractmethod
    def namespace(self) -> str:
        pass

    @abstractmethod
    async def load_session(self, device: DeviceInformation) -> Optional[Session]:
        """
        TODO
        """

        pass

    @abstractmethod
    async def build_session_active(self, device: DeviceInformation, bundle: Bundle) -> Session:
        """
        TODO

        Warning:
            This method may be called for a device which already has a session. In that case, the original
            session must remain in storage and must remain loadable via :meth:`load_session`. Only upon
            calling :meth:`persist` on the new session, the old session must be overwritten with the new one.
            In summary, multiple sessions for the same device can exist in memory, while only one session per
            device can exist in storage, which can be controlled using the :meth:`persist` method.
        """

        pass

    @abstractmethod
    async def build_session_passive(self, device: DeviceInformation, key_exchange: KeyExchange) -> Session:
        """
        TODO

        Warning:
            This method may be called for a device which already has a session. In that case, the original
            session must remain in storage and must remain loadable via :meth:`load_session`. Only upon
            calling :meth:`persist` on the new session, the old session must be overwritten with the new one.
            In summary, multiple sessions for the same device can exist in memory, while only one session per
            device can exist in storage, which can be controlled using the :meth:`persist` method.
        """

        pass

    @abstractmethod
    async def key_exchange_builds_session(self, key_exchange: KeyExchange, session: Session) -> bool:
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
    async def encrypt_empty_message(self, session: Session) -> Message:
        """
        TODO
        """

        pass

    @abstractmethod
    async def decrypt_message(
        self,
        session: Session,
        encrypted: Encrypted,
        max_num_per_session_skipped_keys: int,
        max_num_per_message_skipped_keys: int
    ) -> Plaintext:
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
    async def hide_pre_key(self, session: Session) -> bool:
        """
        TODO
        """

        pass

    @abstractmethod
    async def delete_pre_key(self, session: Session) -> bool:
        """
        TODO
        """

        pass

    @abstractmethod
    async def delete_hidden_pre_keys(self) -> Any:
        """
        TODO
        """

        pass

    @abstractmethod
    async def refill_pre_keys(self, refill_threshold: int) -> Any:
        """
        TODO
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

    @abstractmethod
    async def purge_bare_jid(self, bare_jid: str) -> Any:
        """
        Delete all data corresponding to an XMPP account.

        Args:
            bare_jid: Delete all data corresponding to this bare JID.

        Returns:
            Anything, the return value is ignored.
        """

        pass
