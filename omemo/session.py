from abc import ABC, abstractmethod
from typing import Any, Optional

from .message import KeyExchange

# TODO: Move "complex" API to Backend and add documentation about the motivation for doing that
class Session(ABC):
    """
    TODO

    Warning:
        Changes to a session may only be persisted when :meth:`persist` is called.
    
    Warning:
        Multiple sessions for the same device can exist in memory, however only one session per device can
        exist in storage. Which one of the in-memory sessions is persisted in storage is controlled by calling
        the :meth:`persist` method.
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
    def identity_key(self) -> bytes:
        pass

    @abstractmethod
    async def persist(self) -> Any:
        """
        TODO
        """

        pass

    @property
    @abstractmethod
    def key_exchange(self) -> Optional[KeyExchange]:
        """
        TODO
        """

        pass

    @abstractmethod
    def set_key_exchange(self, key_exchange: KeyExchange) -> Any:
        """
        TODO
        """

        pass

    @abstractmethod
    def delete_key_exchange(self) -> Any:
        """
        TODO
        """

        pass

    @abstractmethod
    def built_by_key_exchange(self, key_exchange: KeyExchange) -> bool:
        """
        TODO
        """

        # TODO: Could this just be KeyExchange.__eq__?
        pass

    @property
    @abstractmethod
    def receiving_chain_length(self) -> int:
        """
        TODO
        """

        pass

    @property
    @abstractmethod
    def sending_chain_length(self) -> int:
        """
        TODO
        """

        pass
