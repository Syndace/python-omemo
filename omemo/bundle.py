from abc import ABC, abstractmethod

class Bundle(ABC):
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
