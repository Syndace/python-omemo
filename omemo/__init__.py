from typing import TYPE_CHECKING

from .version import __version__
from .project import   project

from .backend import Backend, BackendException, KeyExchangeFailed
from .bundle import Bundle
from .message import Content, KeyExchange, KeyMaterial, Message

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
    BundleDeletionFailed,
    DeviceListUploadFailed,
    DeviceListDownloadFailed,
    MessageSendingFailed,
    
    SessionManager
)

from .storage import Maybe, Nothing, Storage, StorageException
from .types import DeviceInformation, OMEMOException, TrustLevel
if TYPE_CHECKING: from .types import JSONType