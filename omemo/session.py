from abc import ABC, abstractmethod
import enum
from typing import Optional

from .message import KeyExchange


__all__ = [
    "Initiation",
    "Session"
]


@enum.unique
class Initiation(enum.Enum):
    """
    Enumeration identifying whether a session was built through active or passive session initiation.
    """

    ACTIVE: str = "ACTIVE"
    PASSIVE: str = "PASSIVE"


class Session(ABC):
    """
    Class representing an OMEMO session. Used to encrypt/decrypt key material for/from a single
    recipient/sender device in a perfectly forwared secure manner.

    Warning:
        Changes to a session may only be persisted when :meth:`~omemo.backend.Backend.store_session` is
        called.

    Warning:
        Multiple sessions for the same device can exist in memory, however only one session per device can
        exist in storage. Which one of the in-memory sessions is persisted in storage is controlled by calling
        the :meth:`~omemo.backend.Backend.store_session` method.

    Note:
        The API of the :class:`Session` class was intentionally kept thin. All "complex" interactions with
        session objects happen via methods of :class:`~omemo.backend.Backend`. This allows backend
        implementors to have the :class:`Session` class be a simple "stupid" data holding structure type,
        while all of the more complex logic is located in the implementation of the
        :class:`~omemo.backend.Backend` class itself. Backend implementations  are obviously free to implement
        logic on their respective :class:`Session` implementations and forward calls to them from the
        :class:`~omemo.backend.Backend` methods.
    """

    @property
    @abstractmethod
    def namespace(self) -> str:
        pass

    @property
    @abstractmethod
    def bare_jid(self) -> str:
        pass

    @property
    @abstractmethod
    def device_id(self) -> int:
        pass

    @property
    @abstractmethod
    def initiation(self) -> Initiation:
        """
        Returns:
            Whether this session was actively initiated or passively.
        """

    @property
    @abstractmethod
    def confirmed(self) -> bool:
        """
        In case this session was built through active session initiation, this flag should indicate whether
        the session initiation has been "confirmed", i.e. at least one message was received and decrypted
        using this session.
        """

    @property
    @abstractmethod
    def key_exchange(self) -> KeyExchange:
        """
        Either the key exchange information received during passive session building, or the key exchange
        information created as part of active session building. The key exchange information is needed by the
        protocol for stability reasons, to make sure that all sides can build the session, even if messages
        are lost or received out of order.

        Returns:
            The key exchange information associated with this session.
        """

    @property
    @abstractmethod
    def receiving_chain_length(self) -> Optional[int]:
        """
        Returns:
            The length of the receiving chain, if it exists, used for own staleness detection.
        """

    @property
    @abstractmethod
    def sending_chain_length(self) -> int:
        """
        Returns:
            The length of the sending chain, used for staleness detection of other devices.
        """
