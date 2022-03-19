from abc import ABCMeta, abstractmethod
from typing import Any

class Session(metaclass=ABCMeta):
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