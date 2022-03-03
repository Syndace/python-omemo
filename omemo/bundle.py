from abc import ABC, abstractmethod

class Bundle(ABC):
    @property
    @abstractmethod
    def namespace() -> str:
        pass
