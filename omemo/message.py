from abc import ABC, abstractmethod
from typing import Optional, Union

class Encrypted(ABC):
    pass

class KeyExchange(ABC):
    @property
    @abstractmethod
    def encrypted(self) -> Encrypted:
        pass

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

    @abstractmethod
    def get_submessage(self, bare_jid: str, device_id: int) -> Optional[Union[Encrypted, KeyExchange]]:
        pass
