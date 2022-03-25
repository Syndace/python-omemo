import enum
from typing import Dict, List, Mapping, NamedTuple, Optional, Set, Union


class OMEMOException(Exception):
    """
    Parent type for all custom exceptions in this library.
    """


class DeviceInformation(NamedTuple):
    # pylint: disable=invalid-name
    """
    Structure containing information about a single OMEMO device.
    """

    namespaces: Set[str]
    active: Dict[str, bool]
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

    TRUSTED = 1
    DISTRUSTED = 2
    UNDECIDED = 3


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
JSONType1 = Union[Primitives, List[Primitives], Mapping[str, Primitives]]
JSONType = Union[Primitives, List[JSONType1], Mapping[str, JSONType1]]


__all__ = [  # pylint: disable=unused-variable
    DeviceInformation.__name__,
    "JSONType",
    OMEMOException.__name__,
    TrustLevel.__name__
]
