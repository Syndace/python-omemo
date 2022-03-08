from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Generic, Optional, Type, TypeVar

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
            raise Nothing("Maybe.fromJust: Nothing") # -- yuck

    def maybe(self, default: V) -> V:
        try:
            return self.__value
        except AttributeError:
            return default
    
    def fmap(self, f: Callable[[V], V2]) -> "Maybe[V2]":
        try:
            value = self.__value
        except AttributeError:
            return Maybe.nothing()

        return Maybe.just(f(value))

T = TypeVar("T")
def check_primitive_type(key: str, value: JSONType, type: Type[T]) -> T:
    if isinstance(value, type):
        return value
    raise TypeError("The value stored for key {} is not a {}: {}".format(key, type, value))

class Storage(ABC): # TODO: Add Raises StorageException everywhere
    """
    # TODO
    """

    def __init__(self, disable_cache: bool = False):
        """
        # TODO
        """

        self.__cache: Optional[Dict[str, Maybe[JSONType]]] = None if disable_cache else {}

    @abstractmethod
    async def _load(self, key: str) -> Maybe[JSONType]:
        """
        TODO
        """

        raise NotImplementedError("Create a subclass of Storage and implement `_load`.")

    @abstractmethod
    async def _store(self, key: str, value: JSONType) -> Any:
        """
        TODO
        """

        raise NotImplementedError("Create a subclass of Storage and implement `_store`.")

    @abstractmethod
    async def _delete(self, key: str) -> Any:
        """
        TODO
        """

        raise NotImplementedError("Create a subclass of Storage and implement `_delete`.")

    async def load(self, key: str) -> Maybe[JSONType]:
        """
        TODO
        """

        try:
            return self.__cache[key]
        except (TypeError, KeyError):
            pass

        value = await self._load(key)
        try:
            self.__cache[key] = value
        except TypeError:
            pass
        return value

    async def store(self, key: str, value: JSONType) -> None:
        """
        TODO
        """

        await self._store(key, value)

        try:
            self.__cache[key] = Maybe.just(value)
        except TypeError:
            pass

    async def delete_device(self, key: str) -> None:
        """
        TODO
        """

        await self._delete(key)

        try:
            self.__cache[key] = Maybe.nothing()
        except TypeError:
            pass

    async def load_int(self, key: str) -> Maybe[int]:
        """
        Variation of :meth:`load` for loading specifically int values.
        """

        return (await self.load(key)).fmap(lambda value: check_primitive_type(key, value, int))

    async def load_str(self, key: str) -> Maybe[str]:
        """
        Variation of :meth:`load` for loading specifically str values.
        """

        return (await self.load(key)).fmap(lambda value: check_primitive_type(key, value, str))
