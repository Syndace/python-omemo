import enum
from typing import Dict, NamedTuple, Optional, Protocol, Set, Type, TYPE_CHECKING, Union

class OMEMOException(Exception):
    """
    Parent type for all custom exceptions in this library.
    """

class DeviceInformation(NamedTuple):
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

    Trusted    = 1
    Distrusted = 2
    Undecided  = 3

# Thanks @vanburgerberg - https://github.com/python/typing/issues/182
if TYPE_CHECKING:
    class JSONArray(list[JSONType], Protocol):  # type: ignore
        __class__: Type[list[JSONType]]  # type: ignore

    class JSONObject(dict[str, JSONType], Protocol):  # type: ignore
        __class__: Type[dict[str, JSONType]]  # type: ignore

    JSONType = Union[None, float, int, str, bool, JSONArray, JSONObject]