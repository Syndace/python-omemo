from abc import ABCMeta, abstractmethod
from typing import Any

class Session(metaclass=ABCMeta):
    """
    TODO

    Warning:
        Changes to a session may only be persisted when :meth:`persist` is called. Dynamic loading of values
        is allowed, dynamic storing is not.
    """

    @property
    @abstractmethod
    def namespace() -> str:
        pass

    @property
    @abstractmethod
    def bare_jid() -> str:
        pass

    @property
    @abstractmethod
    def device_id() -> int:
        pass

    @property
    @abstractmethod
    def identity_key() -> bytes:
        pass

    @abstractmethod
    async def persist(self) -> Any:
        """
        TODO
        """

        pass