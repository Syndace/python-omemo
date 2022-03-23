from abc import ABC, abstractmethod
import base64
import copy
from typing import Any, Callable, Dict, Generic, List, Optional, Type, TypeVar, TYPE_CHECKING

from .types import OMEMOException
if TYPE_CHECKING: from .types import JSONType

class StorageException(OMEMOException):
    """
    Parent type for all exceptions specifically raised by methods of :class:`Storage`.
    """

ValueType = TypeVar("ValueType")
MappedValueType = TypeVar("MappedValueType")
MaybeType = TypeVar("MaybeType", bound="Maybe")

class Nothing(Exception):
    """
    Raise by :meth:`from_just`, in case the value of the :class:`Maybe` is not set.
    """

class Maybe(Generic[ValueType]):
    """
    typing's `Optional[A]` is just an alias for `Union[None, A]`, which means if `A` is a union itself that
    allows `None`, the `Optional[A]` doesn't add anything. E.g. `Optional[Optional[X]] = Optional[X]` is true
    for any type `X`. This Maybe class actually differenciates whether a value is set or not.

    All incoming and outgoing values or cloned using :func:`copy.deepcopy`, such that values stored in a Maybe
    instance are not affected by outside application logic.
    """

    def __init__(self):
        # Just the type definitions here
        self.__value: ValueType

    @classmethod
    def just(cls: Type[MaybeType], value: ValueType) -> MaybeType:
        """
        Args:
            value: The value to set.
        
        Returns:
            An instance of :class:`Maybe` with a set value.
        """

        self = cls()
        self.__value = copy.deepcopy(value)
        return self

    @classmethod
    def nothing(cls: Type[MaybeType]) -> MaybeType:
        """
        Returns:
            An instance of :class:`Maybe` without a value.
        """

        return cls()

    def from_just(self) -> ValueType:
        """
        Returns:
            The value stored in this :class:`Maybe`.
        
        Raises:
            Nothing: if no value is set.
        """

        try:
            return copy.deepcopy(self.__value)
        except AttributeError:
            raise Nothing("Maybe.fromJust: Nothing") # -- yuck

    def maybe(self, default: ValueType) -> ValueType:
        """
        Args:
            default: The value to return if no value is set in this :class:`Maybe`.
        
        Returns:
            The value stored in the :class:`Maybe`, or the default value, which is returned by reference.
        """

        try:
            return copy.deepcopy(self.__value)
        except AttributeError:
            return default
    
    def fmap(self, f: Callable[[ValueType], MappedValueType]) -> "Maybe[MappedValueType]":
        """
        Apply a mapping function to the value stored in this :class:`Maybe`, if a value is stored.

        Args:
            f: The mapping function to apply to the value stored in this :class:`Maybe`, if present.
        
        Returns:
            A new :class:`Maybe`, containing either the mapped value or no value, depending on the original
            :class:`Maybe`.
        """

        try:
            value = copy.deepcopy(self.__value)
        except AttributeError:
            return Maybe.nothing()

        return Maybe.just(f(value))

PrimitiveType = TypeVar("PrimitiveType")
PrimitiveKeyType = TypeVar("PrimitiveKeyType")
PrimitiveValueType = TypeVar("PrimitiveValueType")

class Storage(ABC):
    """
    A simple key/value storage class with optional caching (on by default). Keys can be any Python string,
    values any JSON-serializable structure.

    Warning:
        Writing (and deletion) operations must be performed right away, before returning from the method. Such
        operations must not be cached or otherwise deferred.
    
    Warning:
        All parameters must be treated as immutable unless explicitly noted otherwise.
    
    Note:
        The :class:`Maybe` type performs the additional job of cloning stored and returned values, which
        essential to decouple the cached values from the application logic.
    """

    def __init__(self, disable_cache: bool = False):
        """
        Configure caching behaviour of the storage.

        Args:
            disable_cache: Whether to disable the cache, which is on by default. Use this parameter if your
                storage implementation handles caching itself, to avoid pointless double caching.
        """

        self.__cache: Optional[Dict[str, Maybe[JSONType]]] = None if disable_cache else {}

    @abstractmethod
    async def _load(self, key: str) -> Maybe[JSONType]:
        """
        Load a value.

        Args:
            key: The key identifying the value.
        
        Returns:
            The loaded value, if it exists.
        
        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
        """

        raise NotImplementedError("Create a subclass of Storage and implement `_load`.")

    @abstractmethod
    async def _store(self, key: str, value: JSONType) -> Any:
        """
        Store a value.

        Args:
            key: The key identifying the value.
            value: The value to store under the given key.
        
        Returns:
            Anything, the return value is ignored.
        
        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
        """

        raise NotImplementedError("Create a subclass of Storage and implement `_store`.")

    @abstractmethod
    async def _delete(self, key: str) -> Any:
        """
        Delete a value, if it exists.

        Args:
            key: The key identifying the value to delete.
        
        Returns:
            Anything, the return value is ignored.
        
        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
                Do not raise if the key doesn't exist.
        """

        raise NotImplementedError("Create a subclass of Storage and implement `_delete`.")

    async def load(self, key: str) -> Maybe[JSONType]:
        """
        Load a value.

        Args:
            key: The key identifying the value.
        
        Returns:
            The loaded value, if it exists.
        
        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
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
        Store a value.

        Args:
            key: The key identifying the value.
            value: The value to store under the given key.
        
        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
        """

        await self._store(key, value)

        try:
            self.__cache[key] = Maybe.just(value)
        except TypeError:
            pass

    async def delete(self, key: str) -> None:
        """
        Delete a value, if it exists.

        Args:
            key: The key identifying the value to delete.
        
        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
                Do not raise if the key doesn't exist.
        """

        await self._delete(key)

        try:
            self.__cache[key] = Maybe.nothing()
        except TypeError:
            pass

    async def store_bytes(self, key: str, value: bytes) -> None:
        """
        Variation of :meth:`store` for storing specifically bytes values.

        Args:
            key: The key identifying the value.
            value: The value to store under the given key.
        
        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
        """

        await self.store(key, base64.urlsafe_b64encode(value).decode("ASCII"))

    async def load_primitive(self, key: str, type: Type[PrimitiveType]) -> Maybe[PrimitiveType]:
        """
        Variation of :meth:`load` for loading specifically primitive values.

        Args:
            key: The key identifying the value.
            type: The primitive type of the value.
        
        Returns:
            The loaded and type-checked value, if it exists.
        
        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
        """

        def check_type(value: JSONType) -> PrimitiveType:
            if isinstance(value, type):
                return value
            raise TypeError("The value stored for key {} is not a {}: {}".format(key, type, value))

        return (await self.load(key)).fmap(check_type)

    async def load_bytes(self, key: str) -> Maybe[bytes]:
        """
        Variation of :meth:`load` for loading specifically bytes values.

        Args:
            key: The key identifying the value.
        
        Returns:
            The loaded and type-checked value, if it exists.
        
        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
        """

        def check_type(value: JSONType) -> bytes:
            if isinstance(value, str):
                return base64.urlsafe_b64decode(value.encode("ASCII"))
            raise TypeError("The value stored for key {} is not a str/bytes: {}".format(key, value))

        return (await self.load(key)).fmap(check_type)

    async def load_optional(self, key: str, type: Type[PrimitiveType]) -> Maybe[Optional[PrimitiveType]]:
        """
        Variation of :meth:`load` for loading specifically optional primitive values.

        Args:
            key: The key identifying the value.
            type: The primitive type of the optional value.
        
        Returns:
            The loaded and type-checked value, if it exists.
        
        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
        """

        def check_type(value: JSONType) -> Optional[PrimitiveType]:
            if value is None or isinstance(value, type):
                return value
            raise TypeError("The value stored for key {} is not an optional {}: {}".format(key, type, value))

        return (await self.load(key)).fmap(check_type)

    async def load_list(self, key: str, type: Type[PrimitiveType]) -> Maybe[List[PrimitiveType]]:
        """
        Variation of :meth:`load` for loading specifically lists of primitive values.

        Args:
            key: The key identifying the value.
            type: The primitive type of the list elements.
        
        Returns:
            The loaded and type-checked value, if it exists.
        
        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
        """

        def check_type(value: JSONType) -> List[PrimitiveType]:
            if isinstance(value, list) and all(isinstance(element, type) for element in value):
                return value
            raise TypeError("The value stored for key {} is not a list of {}: {}".format(key, type, value))

        return (await self.load(key)).fmap(check_type)

    async def load_dict(
        self,
        key: str,
        key_type: Type[PrimitiveKeyType],
        value_type: Type[PrimitiveValueType]
    ) -> Maybe[Dict[PrimitiveKeyType, PrimitiveValueType]]:
        """
        Variation of :meth:`load` for loading specifically dictionaries of primitive values.

        Args:
            key: The key identifying the value.
            key_type: The primitive type of the dictionary keys.
            value_type: The primitive type of the dictionary values.
        
        Returns:
            The loaded and type-checked value, if it exists.
        
        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
        """

        def check_type(value: JSONType) -> Dict[PrimitiveKeyType, PrimitiveValueType]:
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
