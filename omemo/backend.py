from abc import ABCMeta, abstractmethod
from typing import Any, Generic, Optional, Set, Tuple, TypeVar

from .bundle import Bundle
from .identity_key_pair import IdentityKeyPair
from .message import Content, KeyMaterial, KeyExchange, Message
from .session import Session
from .types import DeviceInformation, OMEMOException

class BackendException(OMEMOException):
    """
    Parent type for all exceptions specific to :class:`Backend`.
    """

class KeyExchangeFailed(BackendException):
    """
    Raised by :meth:`build_session_active` and :meth:`build_session_passive` in case of an error during the
    processing of a key exchange for session building. Known error conditions are:
    - The bundle does not contain and pre keys (active session building)
    - The signature of the signed pre key could not be verified (active session building)
    - An unkown (signed) pre key was referred to (passive session building)

    Additional backend-specific error conditions might exist.
    """

# TODO: Find a better way to handle Message, Bundle etc. subtypes resp. type safety
# TODO: Maybe a serialize/deserialize method for plaintext <-> bytes?

PlaintextType = TypeVar("PlaintextType")
class Backend(Generic[PlaintextType], metaclass=ABCMeta):
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
        Args:
            device: The device whose session to load.

        Returns:
            The session associated with the device, or `None` if such a session does not exist.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `load_session`.")

    @abstractmethod
    async def build_session_active(
        self,
        device: DeviceInformation,
        bundle: Bundle
    ) -> Tuple[Session, KeyExchange]:
        """
        Actively build a session.

        Args:
            device: The device to initiate the key exchange with.
            bundle: The bundle containing the public key material of the other device required for active
                session building.
        
        Returns:
            The newly built session and the key exchange information required by the other device to complete
            the passive part of session building.
        
        Raises:
            KeyExchangeFailed: in case of failure related to the key exchange required for session building.

        Warning:
            This method may be called for a device which already has a session. In that case, the original
            session must remain in storage and must remain loadable via :meth:`load_session`. Only upon
            calling :meth:`persist` on the new session, the old session must be overwritten with the new one.
            In summary, multiple sessions for the same device can exist in memory, while only one session per
            device can exist in storage, which can be controlled using the :meth:`persist` method.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `build_session_active`.")

    @abstractmethod
    async def build_session_passive(self, device: DeviceInformation, key_exchange: KeyExchange) -> Session:
        """
        Passively build a session.

        Args:
            device: The device which actively initiated the key exchange.
            key_exchange: Key exchange information for the passive session building.
        
        Returns:
            The newly built session. Note that the pre key used to initiate this session must somehow be
            associated with the session, such that :meth:`hide_pre_key` and :meth:`delete_pre_key` can work.
        
        Raises:
            KeyExchangeFailed: in case of failure related to the key exchange required for session building.

        Warning:
            This method may be called for a device which already has a session. In that case, the original
            session must remain in storage and must remain loadable via :meth:`load_session`. Only upon
            calling :meth:`persist` on the new session, the old session must be overwritten with the new one.
            In summary, multiple sessions for the same device can exist in memory, while only one session per
            device can exist in storage, which can be controlled using the :meth:`persist` method.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `build_session_passive`.")

    @abstractmethod
    def build_message(
        self,
        content: Content,
        keys: Set[Tuple[KeyMaterial, Optional[KeyExchange]]]
    ) -> Message:
        """
        Args:
            content: The content of the message.
            keys: A set containing one pair of key material and key exchange information per recipient.

        Returns:
            A message instance, bundling the given content, key material and key exchanges.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `build_message`.")

    @abstractmethod
    async def encrypt(self, sessions: Set[Session], plaintext: PlaintextType) -> Tuple[Content, Set[KeyMaterial]]:
        """
        TODO
        """

        pass

    @abstractmethod
    async def encrypt_empty(self, session: Session) -> Tuple[Content, KeyMaterial]:
        """
        TODO
        """

        pass

    @abstractmethod
    async def decrypt(
        self,
        session: Session,
        content: Content,
        key_material: KeyMaterial,
        max_num_per_session_skipped_keys: int,
        max_num_per_message_skipped_keys: int
    ) -> PlaintextType:
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

        raise NotImplementedError("Create a subclass of Backend and implement `signed_pre_key_age`.")

    @abstractmethod
    async def rotate_signed_pre_key(self, identity_key_pair: IdentityKeyPair) -> Any:
        """
        Rotate the signed pre key. Keep the old signed pre key around for one additional rotation period, i.e.
        until this method is called again.

        Args:
            identity_key_pair: The identity key pair of this device, to sign the new signed pre key with.

        Returns:
            Anything, the return value is ignored.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `rotate_signed_pre_key`.")

    @abstractmethod
    async def hide_pre_key(self, session: Session) -> bool:
        """
        Hide a pre key from the bundle returned by :meth:`bundle` and pre key count returned by
        :meth:`get_num_visible_pre_keys`, but keep the pre key for cryptographic operations.

        Args:
            session: A session that was passively built using :meth:`build_session_passive`. Use this session
                to identity the pre key to hide.

        Returns:
            Whether the pre key was hidden. If the pre key doesn't exist (e.g. because it has already been
            deleted), or was already hidden, do not throw an exception, but return `False` instead.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `hide_pre_key`.")

    @abstractmethod
    async def delete_pre_key(self, session: Session) -> bool:
        """
        Delete a pre key.

        Args:
            session: A session that was passively built using :meth:`build_session_passive`. Use this session
                to identity the pre key to delete.

        Returns:
            Whether the pre key was deleted. If the pre key doesn't exist (e.g. because it has already been
            deleted), do not throw an exception, but return `False` instead.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `delete_pre_key`.")

    @abstractmethod
    async def delete_hidden_pre_keys(self) -> Any:
        """
        Delete all pre keys that were previously hidden using :meth:`hide_pre_key`.

        Returns:
            Anything, the return value is ignored.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `delete_hidden_pre_keys`.")

    @abstractmethod
    async def get_num_visible_pre_keys(self) -> int:
        """
        Returns:
            The number of visible pre keys available. The number returned here should match the number of pre
            keys included in the bundle returned by :meth:`bundle`.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `get_num_pre_keys`.")

    @abstractmethod
    async def generate_pre_keys(self, num_pre_keys: int) -> Any:
        """
        Generate and store pre keys.

        Args:
            num_pre_keys: The number of pre keys to generate.
        
        Returns:
            Anything, the return value is ignored.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `generate_pre_keys`.")

    @abstractmethod
    async def bundle(self, bare_jid: str, device_id: int, identity_key: bytes) -> Bundle:
        """
        Args:
            bare_jid: The bare JID of this XMPP account, to be included in the bundle.
            device_id: The id of this device, to be included in the bundle.
            identity_key: The identity key assigned to this device, to be included in the bundle.

        Returns:
            The bundle containing public information about the cryptographic state of this backend.
            
        Warning:
            Do not include pre keys hidden by :meth:`hide_pre_key` in the bundle!
        """

        raise NotImplementedError("Create a subclass of Backend and implement `bundle`.")

    @abstractmethod
    async def purge(self) -> Any:
        """
        Remove all data related to this backend from the storage.

        Returns:
            Anything, the return value is ignored.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `purge`.")

    @abstractmethod
    async def purge_bare_jid(self, bare_jid: str) -> Any:
        """
        Delete all data corresponding to an XMPP account.

        Args:
            bare_jid: Delete all data corresponding to this bare JID.

        Returns:
            Anything, the return value is ignored.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `purge_bare_jid`.")
