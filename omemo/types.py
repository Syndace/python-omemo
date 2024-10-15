# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations

import enum
from typing import FrozenSet, List, Mapping, NamedTuple, Optional, Tuple, Union


__all__ = [
    "AsyncFramework",
    "DeviceInformation",
    "JSONType",
    "OMEMOException",
    "TrustLevel"
]


@enum.unique
class AsyncFramework(enum.Enum):
    """
    Frameworks for asynchronous code supported by python-omemo.
    """

    ASYNCIO: str = "ASYNCIO"
    TWISTED: str = "TWISTED"


class OMEMOException(Exception):
    """
    Parent type for all custom exceptions in this library.
    """


class DeviceInformation(NamedTuple):
    # pylint: disable=invalid-name
    """
    Structure containing information about a single OMEMO device.
    """

    namespaces: FrozenSet[str]
    active: FrozenSet[Tuple[str, bool]]
    bare_jid: str
    device_id: int
    identity_key: bytes
    trust_level_name: str
    label: Optional[str]


@enum.unique
class TrustLevel(enum.Enum):
    """
    The three core trust levels.
    """

    TRUSTED: str = "TRUSTED"
    DISTRUSTED: str = "DISTRUSTED"
    UNDECIDED: str = "UNDECIDED"


# # Thanks @vanburgerberg - https://github.com/python/typing/issues/182
# if TYPE_CHECKING:
#     class JSONArray(list[JSONType], Protocol):  # type: ignore
#         __class__: Type[list[JSONType]]  # type: ignore
#
#     class JSONObject(dict[str, JSONType], Protocol):  # type: ignore
#         __class__: Type[dict[str, JSONType]]  # type: ignore
#
#     JSONType = Union[None, float, int, str, bool, JSONArray, JSONObject]

# Sadly @vanburgerberg's solution doesn't seem to like Dict[str, bool], thus for now an incomplete JSON
# type with finite levels of depth.
Primitives = Union[None, float, int, str, bool]
JSONType2 = Union[Primitives, List[Primitives], Mapping[str, Primitives]]
JSONType1 = Union[Primitives, List[JSONType2], Mapping[str, JSONType2]]
JSONType = Union[Primitives, List[JSONType1], Mapping[str, JSONType1]]
