from abc import ABC, abstractmethod
from typing import Optional, Set, Tuple

class Content(ABC):
    pass

class KeyMaterial(ABC):
    @property
    @abstractmethod
    def bare_jid(self) -> str:
        pass

    @property
    @abstractmethod
    def device_id(self) -> int:
        pass

class KeyExchange(ABC):
    @property
    @abstractmethod
    def identity_key(self) -> bytes:
        pass

class Message(ABC):
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
