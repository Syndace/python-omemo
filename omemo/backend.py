from abc import ABCMeta, abstractmethod
from typing import Generic, TypeVar

Plaintext = TypeVar("Plaintext")
class Backend(Generic[Plaintext], metaclass=ABCMeta):
    @property
    @abstractmethod
    def namespace() -> str:
        pass
