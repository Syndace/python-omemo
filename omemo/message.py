from abc import ABC, abstractmethod
from typing import Optional

class Content(ABC):
    pass

class KeyMaterial(ABC):
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
    def sender_bare_jid(self) -> str:
        pass

    @property
    @abstractmethod
    def sender_device_id(self) -> int:
        pass

    @property
    @abstractmethod
    def content(self) -> Content:
        pass

    @abstractmethod
    def get_key_material(self, bare_jid: str, device_id: int) -> Optional[KeyMaterial]:
        pass

    @abstractmethod
    def get_key_exchange(self, bare_jid: str, device_id: int) -> Optional[KeyExchange]:
        pass
