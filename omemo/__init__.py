from .version import __version__
from .project import project

from .backend import Backend, BackendException, DecryptionFailed, KeyExchangeFailed, TooManySkippedMessageKeys
from .bundle import Bundle
from .message import Content, EncryptedKeyMaterial, KeyExchange, Message

from .session_manager import (
    SessionManagerException,

    TrustDecisionFailed,
    StillUndecided,
    NoEligibleDevices,

    MessageNotForUs,
    SenderNotFound,
    SenderDistrusted,
    NoSession,
    PublicDataInconsistency,

    UnknownTrustLevel,
    UnknownNamespace,

    XMPPInteractionFailed,
    BundleUploadFailed,
    BundleDownloadFailed,
    BundleNotFound,
    BundleDeletionFailed,
    DeviceListUploadFailed,
    DeviceListDownloadFailed,
    MessageSendingFailed,

    SessionManager
)

from .storage import Just, Maybe, Nothing, NothingException, Storage, StorageException
from .types import AsyncFramework, DeviceInformation, JSONType, OMEMOException, TrustLevel

# Fun:
# https://github.com/PyCQA/pylint/issues/6006
# https://github.com/python/mypy/issues/10198
__all__ = [  # pylint: disable=unused-variable
    # .version
    "__version__",

    # .project
    "project",

    # .backend
    "Backend",
    "BackendException",
    "DecryptionFailed",
    "KeyExchangeFailed",
    "TooManySkippedMessageKeys",

    # .bundle
    "Bundle",

    # .message
    "Content",
    "EncryptedKeyMaterial",
    "KeyExchange",
    "Message",

    # .session_manager
    "SessionManagerException",

    "TrustDecisionFailed",
    "StillUndecided",
    "NoEligibleDevices",

    "MessageNotForUs",
    "SenderNotFound",
    "SenderDistrusted",
    "NoSession",
    "PublicDataInconsistency",

    "UnknownTrustLevel",
    "UnknownNamespace",

    "XMPPInteractionFailed",
    "BundleUploadFailed",
    "BundleDownloadFailed",
    "BundleNotFound",
    "BundleDeletionFailed",
    "DeviceListUploadFailed",
    "DeviceListDownloadFailed",
    "MessageSendingFailed",

    "SessionManager",

    # .storage
    "Just",
    "Maybe",
    "Nothing",
    "NothingException",
    "Storage",
    "StorageException",

    # .types
    "AsyncFramework",
    "DeviceInformation",
    "JSONType",
    "OMEMOException",
    "TrustLevel"
]
