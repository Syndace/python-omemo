from __future__ import annotations

import enum
from typing import FrozenSet, List, Mapping, NamedTuple, Optional, Tuple, Union
from typing_extensions import TypeAlias


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

    ASYNCIO = "ASYNCIO"
    TWISTED = "TWISTED"


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

    TRUSTED = "TRUSTED"
    DISTRUSTED = "DISTRUSTED"
    UNDECIDED = "UNDECIDED"


JSONType: TypeAlias = Union[Mapping[str, "JSONType"], List["JSONType"], str, int, float, bool, None]
