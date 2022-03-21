from abc import ABC, abstractmethod
from typing import Optional, Set, Tuple

class Content(ABC):
    """
    TODO
    """

class KeyMaterial(ABC):
    """
    TODO
    """

    @property
    @abstractmethod
    def bare_jid(self) -> str:
        pass

    @property
    @abstractmethod
    def device_id(self) -> int:
        pass

class KeyExchange(ABC):
    """
    TODO
    """

    @property
    @abstractmethod
    def identity_key(self) -> bytes:
        pass

class Message(ABC):
    """
    TODO
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
    def content(self) -> Content:
        pass

    @property
    @abstractmethod
    def keys(self) -> Set[Tuple[KeyMaterial, Optional[KeyExchange]]]:
        pass
