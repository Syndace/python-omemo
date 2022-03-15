from abc import ABC, abstractmethod
import base64
from typing import Any, Callable, Dict, Generic, List, Optional, Type, TypeVar, TYPE_CHECKING

from .types import OMEMOException
if TYPE_CHECKING: from .types import JSONType

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

P = TypeVar("P")
PK = TypeVar("PK")
PV = TypeVar("PV")
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

    async def store_bytes(self, key: str, value: bytes) -> None:
        """
        TODO
        """

        await self.store(key, base64.urlsafe_b64encode(value).decode("ASCII"))

    async def delete_device(self, key: str) -> None:
        """
        TODO
        """

        await self._delete(key)

        try:
            self.__cache[key] = Maybe.nothing()
        except TypeError:
            pass

    async def load_primitive(self, key: str, type: Type[P]) -> Maybe[P]:
        """
        Variation of :meth:`load` for loading specifically primitive values.
        """

        def check_type(value: JSONType) -> P:
            if isinstance(value, type):
                return value
            raise TypeError("The value stored for key {} is not a {}: {}".format(key, type, value))

        return (await self.load(key)).fmap(check_type)

    async def load_bytes(self, key: str) -> Maybe[bytes]:
        """
        Variation of :meth:`load` for loading specifically bytes values.
        """

        def check_type(value: JSONType) -> bytes:
            if isinstance(value, str):
                return base64.urlsafe_b64decode(value.encode("ASCII"))
            raise TypeError("The value stored for key {} is not a str/bytes: {}".format(key, value))

        return (await self.load(key)).fmap(check_type)

    async def load_optional(self, key: str, type: Type[P]) -> Maybe[Optional[P]]:
        """
        Variation of :meth:`load` for loading specifically optional primitive values.
        """

        def check_type(value: JSONType) -> Optional[P]:
            if value is None or isinstance(value, type):
                return value
            raise TypeError("The value stored for key {} is not an optional {}: {}".format(key, type, value))

        return (await self.load(key)).fmap(check_type)

    async def load_list(self, key: str, type: Type[P]) -> Maybe[List[P]]:
        """
        Variation of :meth:`load` for loading specifically lists of primitive values.
        """

        def check_type(value: JSONType) -> List[P]:
            if isinstance(value, list) and all(isinstance(element, type) for element in value):
                return value
            raise TypeError("The value stored for key {} is not a list of {}: {}".format(key, type, value))

        return (await self.load(key)).fmap(check_type)

    async def load_dict(self, key: str, key_type: Type[PK], value_type: Type[PV]) -> Maybe[Dict[PK, PV]]:
        """
        Variation of :meth:`load` for loading specifically dictionaries of primitive values.
        """

        def check_type(value: JSONType) -> Dict[PK, PV]:
            if isinstance(value, dict):
                if all(isinstance(pk, key_type) and isinstance(pv, value_type) for pk, pv in value.items()):
                    return value
            raise TypeError("The value stored for key {} is not a dict of {} / {}: {}".format(
                key,
                key_type,
                value_type,
                value
            ))

        return (await self.load(key)).fmap(check_type)
