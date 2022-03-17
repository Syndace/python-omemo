from abc import ABC, abstractmethod

class Bundle(ABC):
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