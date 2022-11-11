# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations  # pylint: disable=unused-variable

from abc import ABC, abstractmethod
import base64
import copy
from typing import Callable, Dict, Generic, List, Optional, Type, TypeVar, Union, cast

from .types import JSONType, OMEMOException


__all__ = [  # pylint: disable=unused-variable
    "Just",
    "Maybe",
    "Nothing",
    "NothingException",
    "Storage",
    "StorageException"
]


class StorageException(OMEMOException):
    """
    Parent type for all exceptions specifically raised by methods of :class:`Storage`.
    """


ValueTypeT = TypeVar("ValueTypeT")
DefaultTypeT = TypeVar("DefaultTypeT")
MappedValueTypeT = TypeVar("MappedValueTypeT")


class Maybe(ABC, Generic[ValueTypeT]):
    """
    typing's `Optional[A]` is just an alias for `Union[None, A]`, which means if `A` is a union itself that
    allows `None`, the `Optional[A]` doesn't add anything. E.g. `Optional[Optional[X]] = Optional[X]` is true
    for any type `X`. This Maybe class actually differenciates whether a value is set or not.

    All incoming and outgoing values or cloned using :func:`copy.deepcopy`, such that values stored in a Maybe
    instance are not affected by outside application logic.
    """

    @property
    @abstractmethod
    def is_just(self) -> bool:
        """
        Returns:
            Whether this is a :class:`Just`.
        """

    @property
    @abstractmethod
    def is_nothing(self) -> bool:
        """
        Returns:
            Whether this is a :class:`Nothing`.
        """

    @abstractmethod
    def from_just(self) -> ValueTypeT:
        """
        Returns:
            The value if this is a :class:`Just`.

        Raises:
            NothingException: if this is a :class:`Nothing`.
        """

    @abstractmethod
    def maybe(self, default: DefaultTypeT) -> Union[ValueTypeT, DefaultTypeT]:
        """
        Args:
            default: The value to return if this is in instance of :class:`Nothing`.

        Returns:
            The value if this is a :class:`Just`, or the default value if this is a :class:`Nothing`. The
            default is returned by reference in that case.
        """

    @abstractmethod
    def fmap(self, function: Callable[[ValueTypeT], MappedValueTypeT]) -> "Maybe[MappedValueTypeT]":
        """
        Apply a mapping function.

        Args:
            function: The mapping function.

        Returns:
            A new :class:`Just` containing the mapped value if this is a :class:`Just`. A new :class:`Nothing`
            if this is a :class:`Nothing`.
        """


class NothingException(Exception):
    """
    Raised by :meth:`Maybe.from_just`, in case the :class:`Maybe` is a :class:`Nothing`.
    """


class Nothing(Maybe[ValueTypeT]):
    """
    A :class:`Maybe` that does not hold a value.
    """

    def __init__(self) -> None:
        """
        Initialize a :class:`Nothing`, representing an empty :class:`Maybe`.
        """

    @property
    def is_just(self) -> bool:
        return False

    @property
    def is_nothing(self) -> bool:
        return True

    def from_just(self) -> ValueTypeT:
        raise NothingException("Maybe.fromJust: Nothing")  # -- yuck

    def maybe(self, default: DefaultTypeT) -> DefaultTypeT:
        return default

    def fmap(self, function: Callable[[ValueTypeT], MappedValueTypeT]) -> "Nothing[MappedValueTypeT]":
        return Nothing()


class Just(Maybe[ValueTypeT]):
    """
    A :class:`Maybe` that does hold a value.
    """

    def __init__(self, value: ValueTypeT) -> None:
        """
        Initialize a :class:`Just`, representing a :class:`Maybe` that holds a value.

        Args:
            value: The value to store in this :class:`Just`.
        """

        self.__value = copy.deepcopy(value)

    @property
    def is_just(self) -> bool:
        return True

    @property
    def is_nothing(self) -> bool:
        return False

    def from_just(self) -> ValueTypeT:
        return copy.deepcopy(self.__value)

    def maybe(self, default: DefaultTypeT) -> ValueTypeT:
        return copy.deepcopy(self.__value)

    def fmap(self, function: Callable[[ValueTypeT], MappedValueTypeT]) -> "Just[MappedValueTypeT]":
        return Just(function(copy.deepcopy(self.__value)))


PrimitiveTypeT = TypeVar("PrimitiveTypeT", None, float, int, str, bool)


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

    @abstractmethod
    async def _store(self, key: str, value: JSONType) -> None:
        """
        Store a value.

        Args:
            key: The key identifying the value.
            value: The value to store under the given key.

        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
        """

    @abstractmethod
    async def _delete(self, key: str) -> None:
        """
        Delete a value, if it exists.

        Args:
            key: The key identifying the value to delete.

        Raises:
            StorageException: if any kind of storage operation failed. Feel free to raise a subclass instead.
                Do not raise if the key doesn't exist.
        """

    async def load(self, key: str) -> Maybe[JSONType]:
        """
        Load a value.

        Args:
            key: The key identifying the value.

        Returns:
            The loaded value, if it exists.

        Raises:
            StorageException: if any kind of storage operation failed. Forwarded from :meth:`_load`.
        """

        if self.__cache is not None and key in self.__cache:
            return self.__cache[key]

        value = await self._load(key)
        if self.__cache is not None:
            self.__cache[key] = value
        return value

    async def store(self, key: str, value: JSONType) -> None:
        """
        Store a value.

        Args:
            key: The key identifying the value.
            value: The value to store under the given key.

        Raises:
            StorageException: if any kind of storage operation failed. Forwarded from :meth:`_store`.
        """

        await self._store(key, value)

        if self.__cache is not None:
            self.__cache[key] = Just(value)

    async def delete(self, key: str) -> None:
        """
        Delete a value, if it exists.

        Args:
            key: The key identifying the value to delete.

        Raises:
            StorageException: if any kind of storage operation failed. Does not raise if the key doesn't
                exist. Forwarded from :meth:`_delete`.
        """

        await self._delete(key)

        if self.__cache is not None:
            self.__cache[key] = Nothing()

    async def store_bytes(self, key: str, value: bytes) -> None:
        """
        Variation of :meth:`store` for storing specifically bytes values.

        Args:
            key: The key identifying the value.
            value: The value to store under the given key.

        Raises:
            StorageException: if any kind of storage operation failed. Forwarded from :meth:`_store`.
        """

        await self.store(key, base64.urlsafe_b64encode(value).decode("ASCII"))

    async def load_primitive(self, key: str, primitive: Type[PrimitiveTypeT]) -> Maybe[PrimitiveTypeT]:
        """
        Variation of :meth:`load` for loading specifically primitive values.

        Args:
            key: The key identifying the value.
            primitive: The primitive type of the value.

        Returns:
            The loaded and type-checked value, if it exists.

        Raises:
            StorageException: if any kind of storage operation failed. Forwarded from :meth:`_load`.
        """

        def check_type(value: JSONType) -> PrimitiveTypeT:
            if isinstance(value, primitive):
                return value
            raise TypeError(f"The value stored for key {key} is not a {primitive}: {value}")

        return (await self.load(key)).fmap(check_type)

    async def load_bytes(self, key: str) -> Maybe[bytes]:
        """
        Variation of :meth:`load` for loading specifically bytes values.

        Args:
            key: The key identifying the value.

        Returns:
            The loaded and type-checked value, if it exists.

        Raises:
            StorageException: if any kind of storage operation failed. Forwarded from :meth:`_load`.
        """

        def check_type(value: JSONType) -> bytes:
            if isinstance(value, str):
                return base64.urlsafe_b64decode(value.encode("ASCII"))
            raise TypeError(f"The value stored for key {key} is not a str/bytes: {value}")

        return (await self.load(key)).fmap(check_type)

    async def load_optional(
        self,
        key: str,
        primitive: Type[PrimitiveTypeT]
    ) -> Maybe[Optional[PrimitiveTypeT]]:
        """
        Variation of :meth:`load` for loading specifically optional primitive values.

        Args:
            key: The key identifying the value.
            primitive: The primitive type of the optional value.

        Returns:
            The loaded and type-checked value, if it exists.

        Raises:
            StorageException: if any kind of storage operation failed. Forwarded from :meth:`_load`.
        """

        def check_type(value: JSONType) -> Optional[PrimitiveTypeT]:
            if value is None or isinstance(value, primitive):
                return value
            raise TypeError(f"The value stored for key {key} is not an optional {primitive}: {value}")

        return (await self.load(key)).fmap(check_type)

    async def load_list(self, key: str, primitive: Type[PrimitiveTypeT]) -> Maybe[List[PrimitiveTypeT]]:
        """
        Variation of :meth:`load` for loading specifically lists of primitive values.

        Args:
            key: The key identifying the value.
            primitive: The primitive type of the list elements.

        Returns:
            The loaded and type-checked value, if it exists.

        Raises:
            StorageException: if any kind of storage operation failed. Forwarded from :meth:`_load`.
        """

        def check_type(value: JSONType) -> List[PrimitiveTypeT]:
            if isinstance(value, list) and all(isinstance(element, primitive) for element in value):
                return cast(List[PrimitiveTypeT], value)
            raise TypeError(f"The value stored for key {key} is not a list of {primitive}: {value}")

        return (await self.load(key)).fmap(check_type)

    async def load_dict(
        self,
        key: str,
        primitive: Type[PrimitiveTypeT]
    ) -> Maybe[Dict[str, PrimitiveTypeT]]:
        """
        Variation of :meth:`load` for loading specifically dictionaries of primitive values.

        Args:
            key: The key identifying the value.
            primitive: The primitive type of the dictionary values.

        Returns:
            The loaded and type-checked value, if it exists.

        Raises:
            StorageException: if any kind of storage operation failed. Forwarded from :meth:`_load`.
        """

        def check_type(value: JSONType) -> Dict[str, PrimitiveTypeT]:
            if isinstance(value, dict) and all(isinstance(v, primitive) for v in value.values()):
                return cast(Dict[str, PrimitiveTypeT], value)

            raise TypeError(f"The value stored for key {key} is not a dict of {primitive}: {value}")

        return (await self.load(key)).fmap(check_type)
