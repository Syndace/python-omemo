from abc import ABC, abstractmethod

class Message(ABC):
    @property
    @abstractmethod
    def namespace() -> str:
        pass
