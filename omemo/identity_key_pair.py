from typing import Type, TypeVar

from .storage import Storage

IKP = TypeVar("IKP", bound="IdentityKeyPair")
class IdentityKeyPair:
    """
    TODO: Document the transparent handling of Mont vs. Ed
    """

    @property
    def identity_key(self) -> bytes:
        """
        Returns:
            The public part of the identity key pair, in Ed25519 format.
        """

        # TODO
        pass

    @classmethod
    async def get(cls: Type[IKP], storage: Storage) -> IKP:
        """
        Get the identity key pair. Note that there is only ever one identity key pair. All instances of this
        class refer to the same storage locations, thus the same data.

        Args:
            storage: The storage for all OMEMO-related data.

        Returns:
            The identity key pair, which has either been loaded from storage or newly generated.
        """

        # TODO
        pass
