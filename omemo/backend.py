from abc import ABC, abstractmethod
from typing import Any, Generic, Optional, Set, Tuple, TypeVar

from .bundle import Bundle
from .identity_key_pair import IdentityKeyPair
from .message import Content, KeyMaterial, KeyExchange
from .session import Session
from .types import OMEMOException


class BackendException(OMEMOException):
    """
    Parent type for all exceptions specific to :class:`Backend`.
    """


class KeyExchangeFailed(BackendException):
    """
    Raised by :meth:`Backend.build_session_active` and :meth:`Backend.build_session_passive` in case of an
    error during the processing of a key exchange for session building. Known error conditions are:

    * The bundle does not contain and pre keys (active session building)
    * The signature of the signed pre key could not be verified (active session building)
    * An unkown (signed) pre key was referred to (passive session building)

    Additional backend-specific error conditions might exist.
    """


class TooManySkippedMessageKeys(BackendException):
    """
    Raised by :meth:`Backend.decrypt` if a message skips more message keys than allowed.
    """


PlaintextTypeT = TypeVar("PlaintextTypeT")


class Backend(ABC, Generic[PlaintextTypeT]):
    """
    The base class for all backends. A backend is a unit providing the functionality of a certain OMEMO
    version to the core library. Refer to the documentation page :ref:`writing_a_backend` for details about
    the concept and a guide on building your own backend.

    The plaintext generic can be used to choose a convenient type for the plaintext passed/received from the
    encrypt/decrypt methods. This can for example be a stanze type for backend implementations utilizing
    `SCE <https://xmpp.org/extensions/xep-0420.html>`__.

    Warning:
        All parameters must be treated as immutable unless explicitly noted otherwise.

    Note:
        Most methods can raise :class:`~omemo.storage.StorageException` in addition to those exceptions
        listed explicitly.

    Note:
        All usages of "identity key" in the public API refer to the public part of the identity key pair in
        Ed25519 format. Otherwise, "identity key pair" is explicitly used to refer to the full key pair.

    Note:
        For backend implementors: as part of your backend implementation, you are expected to subclass various
        abstract base classes like :class:`~omemo.session.Session`, :class:`~omemo.message.Content`,
        :class:`~omemo.message.KeyMaterial` and :class:`~omemo.message.KeyExchange`. Whenever any of these
        abstract base types appears in a method signature of the :class:`Backend` class, what's actually meant
        is an instance of your respective subclass. This is not correctly expressed through the type system,
        since I couldn't think of a clean way to do so. Adding generics for every single of these types seemed
        not worth the effort. For now, the recommended way to deal with this type inaccuray is to assert the
        types of the affected method parameters, for example::

            async def store_session(self, session: Session) -> Any:
                assert isinstance(session, MySessionImpl)

                ...

        Doing so tells mypy how to deal with the situation. These assertions should never fail.
    """

    @property
    @abstractmethod
    def namespace(self) -> str:
        """
        Returns:
            The namespace provided/handled by this backend implementation.
        """

    @abstractmethod
    async def load_session(self, bare_jid: str, device_id: int) -> Optional[Session]:
        """
        Args:
            bare_jid: The bare JID the device belongs to.
            device_id: The id of the device.

        Returns:
            The session associated with the device, or `None` if such a session does not exist.

        Warning:
            Multiple sessions for the same device can exist in memory, however only one session per device can
            exist in storage. Which one of the in-memory sessions is persisted in storage is controlled by
            calling the :meth:`store_session` method.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `load_session`.")

    @abstractmethod
    async def store_session(self, session: Session) -> Any:
        """
        Store a session, overwriting any previously stored session for the bare JID and device id this session
        belongs to.

        Args:
            session: The session to store.

        Returns:
            Anything, the return value is ignored.

        Warning:
            Multiple sessions for the same device can exist in memory, however only one session per device can
            exist in storage. Which one of the in-memory sessions is persisted in storage is controlled by
            calling this method.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `store_session`.")

    @abstractmethod
    async def build_session_active(
        self,
        bare_jid: str,
        device_id: int,
        bundle: Bundle
    ) -> Tuple[Session, KeyExchange]:
        """
        Actively build a session.

        Args:
            bare_jid: The bare JID the device belongs to.
            device_id: The id of the device.
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
            calling :meth:`store_session`, the old session must be overwritten with the new one. In summary,
            multiple sessions for the same device can exist in memory, while only one session per device can
            exist in storage, which can be controlled using the :meth:`store_session` method.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `build_session_active`.")

    @abstractmethod
    async def build_session_passive(
        self,
        bare_jid: str,
        device_id: int,
        key_exchange: KeyExchange
    ) -> Session:
        """
        Passively build a session.

        Args:
            bare_jid: The bare JID the device belongs to.
            device_id: The id of the device.
            key_exchange: Key exchange information for the passive session building.

        Returns:
            The newly built session. Note that the pre key used to initiate this session must somehow be
            associated with the session, such that :meth:`hide_pre_key` and :meth:`delete_pre_key` can work.

        Raises:
            KeyExchangeFailed: in case of failure related to the key exchange required for session building.

        Warning:
            This method may be called for a device which already has a session. In that case, the original
            session must remain in storage and must remain loadable via :meth:`load_session`. Only upon
            calling :meth:`store_session`, the old session must be overwritten with the new one. In summary,
            multiple sessions for the same device can exist in memory, while only one session per device can
            exist in storage, which can be controlled using the :meth:`store_session` method.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `build_session_passive`.")

    @abstractmethod
    def serialize_plaintext(self, plaintext: PlaintextTypeT) -> bytes:
        """
        Args:
            plaintext: The plaintext to serialize.

        Returns:
            The plaintext serialized to bytes.

        Note:
            Refer to the documentation of the :class:`~omemo.backend.Backend` class for information about the
            ``PlaintextType`` type.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `serialize_plaintext`.")

    @abstractmethod
    async def encrypt(
        self,
        sessions: Set[Session],
        plaintext: bytes
    ) -> Tuple[Content, Set[KeyMaterial]]:
        """
        Encrypt some plaintext symmetrically, and encrypt the corresponding key material once with each
        session.

        Args:
            sessions: The sessions to encrypt the key material with.
            plaintext: The serialized plaintext to encrypt symmetrically.

        Returns:
            The symmetrically encrypted plaintext, and a set containing the encrypted key material for each
            sessions.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `encrypt`.")

    @abstractmethod
    async def encrypt_empty(self, session: Session) -> Tuple[Content, KeyMaterial]:
        """
        Encrypt an empty message for the sole purpose of session manangement/ratchet forwarding/key material
        transportation.

        Args:
            session: The session to encrypt the key material for the empty message with.

        Returns:
            The symmetrically encrypted empty content, and the encrypted key material.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `encrypt_empty`.")

    @abstractmethod
    def deserialize_plaintext(self, plaintext: bytes) -> PlaintextTypeT:
        """
        Args:
            plaintext: The serialized plaintext as bytes.

        Returns:
            The deserialized plaintext.

        Note:
            Refer to the documentation of the :class:`~omemo.backend.Backend` class for information about the
            ``PlaintextType`` type.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `deserialize_plaintext`.")

    @abstractmethod
    async def decrypt(
        self,
        session: Session,
        content: Content,
        key_material: KeyMaterial,
        max_num_per_session_skipped_keys: int,
        max_num_per_message_skipped_keys: int
    ) -> bytes:
        """
        Decrypt some key material using the session, then decrypt the content symmetrically using the key
        material.

        Args:
            session: The session to decrypt the key material with.
            content: The symmetrically encrypted content.
            key_material: The encrypted key material.
            max_num_per_session_skipped_keys: The maximum number of skipped message keys to keep per session.
            max_num_per_message_skipped_keys: The maximum number of skipped message keys allowed in a single
                message.

        Returns:
            The decrypted, yet serialized plaintext.

        Raises:
            TooManySkippedMessageKeys: if the number of message keys skipped by this message exceeds the upper
                limit enforced by `max_num_per_message_skipped_keys`.

        Note:
            When the maximum number of skipped message keys for this session, given by
            `max_num_per_session_skipped_keys`, is exceeded, old skipped message keys are deleted to make
            space for new ones.
        """

        raise NotImplementedError("Create a subclass of Backend and implement `decrypt`.")

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


__all__ = [  # pylint: disable=unused-variable
    Backend.__name__,
    BackendException.__name__,
    KeyExchangeFailed.__name__,
    TooManySkippedMessageKeys.__name__
]
