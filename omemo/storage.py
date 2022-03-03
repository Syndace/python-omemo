from abc import ABCMeta, abstractmethod
from typing import NamedTuple, Optional, Set, Tuple, Dict, Any, TypeVar, Type, Generic

from .types import JSONType, OMEMOException

class StorageException(OMEMOException):
    pass

# typing's Optional[A] is just an alias for Union[None, A], which means if A is a union itself that allows
# None, the Optional[A] doesn't add anything. E.g. Optional[Optional[X]] = Optional[X] is true for any type X.
# This Maybe class actually makes a difference between whether a value is set or not.
V  = TypeVar("V")
V2 = TypeVar("V2")
M  = TypeVar("M", bound="Maybe")

class Nothing(Exception):
    pass

class Maybe(Generic[V]):
    def __init__(self):
        # Just the type definitions here
        self.__value: V

    @classmethod
    def just(cls: Type[M], value: V) -> M:
        # pylint: disable=protected-access
        self = cls()
        self.__value = value
        return self

    @classmethod
    def nothing(cls: Type[M]) -> M:
        return cls()

    def from_just(self) -> V:
        try:
            return self.__value
        except AttributeError:
            raise Nothing # -- yuck

    def fmap(self, f: (value: V) -> V2) -> Maybe[V2]:
        try:
            value = self.__value
        except AttributeError:
            return Maybe.nothing()

        return Maybe.just(f(value))

class Storage(metaclass=ABCMeta): # TODO: Add Raises StorageException everywhere
    """
    # TODO
    """

    def __init__(self, disable_cache: bool = False):
        """
        # TODO
        """

        self.__device_cache: Optional[Dict[str, Maybe[Device]]] = None if disable_cache else {}
        # TODO

    @abstractmethod
    async def load(self, key: str) -> Maybe[JSONType]:
        """
        TODO
        """

        raise NotImplementedError

    @abstractmethod
    async def store(self, key: str, value: JSONType) -> Any:
        """
        TODO
        """

        raise NotImplementedError

    @abstractmethod
    async def delete(self, key: str) -> Any:
        """
        TODO
        """

        raise NotImplementedError

    async def load_device(self, key: str) -> Maybe[Device]:
        """
        TODO
        """

        try:
            return self.__device_cache[key]
        except TypeError, KeyError:
            pass

        return (await self.load(key)).fmap(DeviceModel.load)

    async def store_device(self, key: str, value: Device) -> None:
        """
        TODO
        """

        await self.store(key, DeviceModel.dump(value))

        try:
            self.__device_cache[key] = Maybe.just(value)
        except TypeError:
            pass

    async def delete_device(self, key: str) -> None:
        """
        TODO
        """

        await self.delete(key)

        try:
            self.__device_cache[key] = Maybe.nothing()
        except TypeError:
            pass
