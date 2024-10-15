from abc import ABC, abstractmethod
from typing import Optional, Tuple

from .bundle import Bundle
from .message import Content, EncryptedKeyMaterial, PlainKeyMaterial, KeyExchange
from .session import Session
from .types import OMEMOException


__all__ = [
    "Backend",
    "BackendException",
    "DecryptionFailed",
    "KeyExchangeFailed",
    "TooManySkippedMessageKeys"
]


class BackendException(OMEMOException):
    """
    Parent type for all exceptions specific to :class:`Backend`.
    """


class DecryptionFailed(BackendException):
    """
    Raised by various methods of :class:`Backend` in case of backend-specific failures during decryption.
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
    Raised by :meth:`Backend.decrypt_key_material` if a message skips more message keys than allowed.
    """


class Backend(ABC):
    """
    The base class for all backends. A backend is a unit providing the functionality of a certain OMEMO
    version to the core library.

    Warning:
        Make sure to call :meth:`__init__` from your subclass to configure per-message and per-session skipped
        message key DoS protection thresholds, and respect those thresholds when decrypting key material using
        :meth:`decrypt_key_material`.

    Note:
        Most methods can raise :class:`~omemo.storage.StorageException` in addition to those exceptions
        listed explicitly.

    Note:
        All usages of "identity key" in the public API refer to the public part of the identity key pair in
        Ed25519 format. Otherwise, "identity key pair" is explicitly used to refer to the full key pair.

    Note:
        For backend implementors: as part of your backend implementation, you are expected to subclass various
        abstract base classes like :class:`~omemo.session.Session`, :class:`~omemo.message.Content`,
        :class:`~omemo.message.PlainKeyMaterial`, :class:`~omemo.message.EncryptedKeyMaterial` and
        :class:`~omemo.message.KeyExchange`. Whenever any of these abstract base types appears in a method
        signature of the :class:`Backend` class, what's actually meant is an instance of your respective
        subclass. This is not correctly expressed through the type system, since I couldn't think of a clean
        way to do so. Adding generics for every single of these types seemed not worth the effort. For now,
        the recommended way to deal with this type inaccuray is to assert the types of the affected method
        parameters, for example::

            async def store_session(self, session: Session) -> Any:
                assert isinstance(session, MySessionImpl)

                ...

        Doing so tells mypy how to deal with the situation. These assertions should never fail.

    Note:
        For backend implementors: you can access the identity key pair at any time via
        :meth:`omemo.identity_key_pair.IdentityKeyPair.get`.
    """

    def __init__(
        self,
        max_num_per_session_skipped_keys: int = 1000,
        max_num_per_message_skipped_keys: Optional[int] = None
    ) -> None:
        """
        Args:
            max_num_per_session_skipped_keys: The maximum number of skipped message keys to keep around per
                session. Once the maximum is reached, old message keys are deleted to make space for newer
                ones. Accessible via :attr:`max_num_per_session_skipped_keys`.
            max_num_per_message_skipped_keys: The maximum number of skipped message keys to accept in a single
                message. When set to ``None`` (the default), this parameter defaults to the per-session
                maximum (i.e. the value of the ``max_num_per_session_skipped_keys`` parameter). This parameter
                may only be 0 if the per-session maximum is 0, otherwise it must be a number between 1 and the
                per-session maximum. Accessible via :attr:`max_num_per_message_skipped_keys`.
        """

        if max_num_per_message_skipped_keys == 0 and max_num_per_session_skipped_keys != 0:
            raise ValueError(
                "The number of allowed per-message skipped keys must be nonzero if the number of per-session"
                " skipped keys to keep is nonzero."
            )

        if max_num_per_message_skipped_keys or 0 > max_num_per_session_skipped_keys:
            raise ValueError(
                "The number of allowed per-message skipped keys must not be greater than the number of"
                " per-session skipped keys to keep."
            )

        self.__max_num_per_session_skipped_keys = max_num_per_session_skipped_keys
        self.__max_num_per_message_skipped_keys = max_num_per_session_skipped_keys if \
            max_num_per_message_skipped_keys is None else max_num_per_message_skipped_keys

    @property
    def max_num_per_session_skipped_keys(self) -> int:
        """
        Returns:
            The maximum number of skipped message keys to keep around per session.
        """

        return self.__max_num_per_session_skipped_keys

    @property
    def max_num_per_message_skipped_keys(self) -> int:
        """
        Returns:
            The maximum number of skipped message keys to accept in a single message.
        """

        return self.__max_num_per_message_skipped_keys

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

    @abstractmethod
    async def store_session(self, session: Session) -> None:
        """
        Store a session, overwriting any previously stored session for the bare JID and device id this session
        belongs to.

        Args:
            session: The session to store.

        Warning:
            Multiple sessions for the same device can exist in memory, however only one session per device can
            exist in storage. Which one of the in-memory sessions is persisted in storage is controlled by
            calling this method.
        """

    @abstractmethod
    async def build_session_active(
        self,
        bare_jid: str,
        device_id: int,
        bundle: Bundle,
        plain_key_material: PlainKeyMaterial
    ) -> Tuple[Session, EncryptedKeyMaterial]:
        """
        Actively build a session.

        Args:
            bare_jid: The bare JID the device belongs to.
            device_id: The id of the device.
            bundle: The bundle containing the public key material of the other device required for active
                session building.
            plain_key_material: The key material to encrypt for the recipient as part of the initial key
                exchange/session initiation.

        Returns:
            The newly built session, the encrypted key material and the key exchange information required by
            the other device to complete the passive part of session building. The
            :attr:`~omemo.session.Session.initiation` property of the returned session must return
            :attr:`~omemo.session.Initiation.ACTIVE`. The :attr:`~omemo.session.Session.key_exchange` property
            of the returned session must return the information required by the other party to complete its
            part of the key exchange.

        Raises:
            KeyExchangeFailed: in case of failure related to the key exchange required for session building.

        Warning:
            This method may be called for a device which already has a session. In that case, the original
            session must remain in storage and must remain loadable via :meth:`load_session`. Only upon
            calling :meth:`store_session`, the old session must be overwritten with the new one. In summary,
            multiple sessions for the same device can exist in memory, while only one session per device can
            exist in storage, which can be controlled using the :meth:`store_session` method.
        """

    @abstractmethod
    async def build_session_passive(
        self,
        bare_jid: str,
        device_id: int,
        key_exchange: KeyExchange,
        encrypted_key_material: EncryptedKeyMaterial
    ) -> Tuple[Session, PlainKeyMaterial]:
        """
        Passively build a session.

        Args:
            bare_jid: The bare JID the device belongs to.
            device_id: The id of the device.
            key_exchange: Key exchange information for the passive session building.
            encrypted_key_material: The key material to decrypt as part of the initial key exchange/session
                initiation.

        Returns:
            The newly built session and the decrypted key material. Note that the pre key used to initiate
            this session must somehow be associated with the session, such that :meth:`hide_pre_key` and
            :meth:`delete_pre_key` can work.

        Raises:
            KeyExchangeFailed: in case of failure related to the key exchange required for session building.
            DecryptionFailed: in case of backend-specific failures during decryption of the initial message.

        Warning:
            This method may be called for a device which already has a session. In that case, the original
            session must remain in storage and must remain loadable via :meth:`load_session`. Only upon
            calling :meth:`store_session`, the old session must be overwritten with the new one. In summary,
            multiple sessions for the same device can exist in memory, while only one session per device can
            exist in storage, which can be controlled using the :meth:`store_session` method.
        """

    @abstractmethod
    async def encrypt_plaintext(self, plaintext: bytes) -> Tuple[Content, PlainKeyMaterial]:
        """
        Encrypt some plaintext symmetrically.

        Args:
            plaintext: The plaintext to encrypt symmetrically.

        Returns:
            The encrypted plaintext aka content, as well as the key material needed to decrypt it.
        """

    @abstractmethod
    async def encrypt_empty(self) -> Tuple[Content, PlainKeyMaterial]:
        """
        Encrypt an empty message for the sole purpose of session manangement/ratchet forwarding/key material
        transportation.

        Returns:
            The symmetrically encrypted empty content, and the key material needed to decrypt it.
        """

    @abstractmethod
    async def encrypt_key_material(
        self,
        session: Session,
        plain_key_material: PlainKeyMaterial
    ) -> EncryptedKeyMaterial:
        """
        Encrypt some key material asymmetrically using the session.

        Args:
            session: The session to encrypt the key material with.
            plain_key_material: The key material to encrypt asymmetrically for each recipient.

        Returns:
            The encrypted key material.
        """

    @abstractmethod
    async def decrypt_plaintext(self, content: Content, plain_key_material: PlainKeyMaterial) -> bytes:
        """
        Decrypt some symmetrically encrypted plaintext.

        Args:
            content: The content to decrypt. Not empty, i.e. :attr:`Content.empty` will return ``False``.
            plain_key_material: The key material to decrypt with.

        Returns:
            The decrypted plaintext.

        Raises:
            DecryptionFailed: in case of backend-specific failures during decryption.
        """

    @abstractmethod
    async def decrypt_key_material(
        self,
        session: Session,
        encrypted_key_material: EncryptedKeyMaterial
    ) -> PlainKeyMaterial:
        """
        Decrypt some key material asymmetrically using the session.

        Args:
            session: The session to decrypt the key material with.
            encrypted_key_material: The encrypted key material.

        Returns:
            The decrypted key material

        Raises:
            TooManySkippedMessageKeys: if the number of message keys skipped by this message exceeds the upper
                limit enforced by :attr:`max_num_per_message_skipped_keys`.
            DecryptionFailed: in case of backend-specific failures during decryption.

        Warning:
            Make sure to respect the values of :attr:`max_num_per_session_skipped_keys` and
            :attr:`max_num_per_message_skipped_keys`.

        Note:
            When the maximum number of skipped message keys for this session, given by
            :attr:`max_num_per_session_skipped_keys`, is exceeded, old skipped message keys are deleted to
            make space for new ones.
        """

    @abstractmethod
    async def signed_pre_key_age(self) -> int:
        """
        Returns:
            The age of the signed pre key, i.e. the time elapsed since it was last rotated, in seconds.
        """

    @abstractmethod
    async def rotate_signed_pre_key(self) -> None:
        """
        Rotate the signed pre key. Keep the old signed pre key around for one additional rotation period, i.e.
        until this method is called again.
        """

    @abstractmethod
    async def hide_pre_key(self, session: Session) -> bool:
        """
        Hide a pre key from the bundle returned by :meth:`get_bundle` and pre key count returned by
        :meth:`get_num_visible_pre_keys`, but keep the pre key for cryptographic operations.

        Args:
            session: A session that was passively built using :meth:`build_session_passive`. Use this session
                to identity the pre key to hide.

        Returns:
            Whether the pre key was hidden. If the pre key doesn't exist (e.g. because it has already been
            deleted), or was already hidden, do not throw an exception, but return `False` instead.
        """

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

    @abstractmethod
    async def delete_hidden_pre_keys(self) -> None:
        """
        Delete all pre keys that were previously hidden using :meth:`hide_pre_key`.
        """

    @abstractmethod
    async def get_num_visible_pre_keys(self) -> int:
        """
        Returns:
            The number of visible pre keys available. The number returned here should match the number of pre
            keys included in the bundle returned by :meth:`get_bundle`.
        """

    @abstractmethod
    async def generate_pre_keys(self, num_pre_keys: int) -> None:
        """
        Generate and store pre keys.

        Args:
            num_pre_keys: The number of pre keys to generate.
        """

    @abstractmethod
    async def get_bundle(self, bare_jid: str, device_id: int) -> Bundle:
        """
        Args:
            bare_jid: The bare JID of this XMPP account, to be included in the bundle.
            device_id: The id of this device, to be included in the bundle.

        Returns:
            The bundle containing public information about the cryptographic state of this backend.

        Warning:
            Do not include pre keys hidden by :meth:`hide_pre_key` in the bundle!
        """

    @abstractmethod
    async def purge(self) -> None:
        """
        Remove all data related to this backend from the storage.
        """

    @abstractmethod
    async def purge_bare_jid(self, bare_jid: str) -> None:
        """
        Delete all data corresponding to an XMPP account.

        Args:
            bare_jid: Delete all data corresponding to this bare JID.
        """
