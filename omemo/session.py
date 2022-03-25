from abc import ABC, abstractmethod
from typing import Optional

from .message import KeyExchange

class Session(ABC): # pylint: disable=unused-variable
    """
    Class representing an OMEMO session. Used to encrypt/decrypt key material for/from a single
    recipient/sender device in a perfectly forwared secure manner.

    Warning:
        Changes to a session may only be persisted when :meth:`store_session` is called.

    Warning:
        Multiple sessions for the same device can exist in memory, however only one session per device can
        exist in storage. Which one of the in-memory sessions is persisted in storage is controlled by calling
        the :meth:`store_session` method.

    Note:
        The API of the :class:`Session` class was intentionally kept thin. All "complex" interactions with
        session objects happen via methods of :class:`Backend`. This allows backend implementors to have the
        :class:`Session` class be a simple "stupid" data holding structure type, while all of the more complex
        logic is located in the implementation of the :class:`Backend` class itself. Backend implementations
        are obviously free to implement logic on their respective :class:`Session` implementations and forward
        calls to them from the :class:`Backend` methods.
    """

    @property
    @abstractmethod
    def namespace(self) -> str:
        # pylint: disable=missing-function-docstring
        pass

    @property
    @abstractmethod
    def bare_jid(self) -> str:
        # pylint: disable=missing-function-docstring
        pass

    @property
    @abstractmethod
    def device_id(self) -> int:
        # pylint: disable=missing-function-docstring
        pass

    @property
    @abstractmethod
    def identity_key(self) -> bytes:
        # pylint: disable=missing-function-docstring
        pass

    @property
    @abstractmethod
    def key_exchange(self) -> Optional[KeyExchange]:
        """
        This property allows associating some key exchange information with a session. This can either be the
        key exchange information received during passive session building, or the key exchange information
        created as part of active session building. The key exchange information is needed by the protocol for
        stability reasons, to make sure that all sides can build the session, even if messages are lost or
        received out of order.

        Returns:
            The key exchange information associated with this session, or `None`.

        Note:
            The core library (i.e. :class:`SessionManager`) takes care of setting this property, backend
            implementors only have to care about loading and storing the value in :meth:`load_session` and
            :meth:`store_session`.
        """

    @abstractmethod
    def set_key_exchange(self, value: Optional[KeyExchange]) -> None:
        """
        Override the key exchange information associated with this session. Setter for the `key_exchange`
        property.

        Args:
            value: The key exchange information to associate with this session, or `None`.

        Note:
            The core library (i.e. :class:`SessionManager`) takes care of setting this property, backend
            implementors only have to care about loading and storing the value in :meth:`load_session` and
            :meth:`store_session`.

        Info:
            Not an actual setter, since mypy doesn't support abstract setters:
            `GitHub issue <https://github.com/python/mypy/issues/4165>`__
        """

    @property
    @abstractmethod
    def receiving_chain_length(self) -> int:
        """
        Returns:
            The length of the receiving chain, used for own staleness detection.
        """

    @property
    @abstractmethod
    def sending_chain_length(self) -> int:
        """
        Returns:
            The length of the sending chain, used for staleness detection of other devices.
        """
