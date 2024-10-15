import abc
import enum
from typing import FrozenSet, Optional, Set

from typing_extensions import assert_never

import omemo


__all__ = [
    "BTBVSessionManager",
    "BTBVTrustLevel"
]


@enum.unique
class BTBVTrustLevel(enum.Enum):
    """
    Trust levels modeling Blind Trust Before Verification (BTBV).
    """

    TRUSTED: str = "TRUSTED"
    BLINDLY_TRUSTED: str = "BLINDLY_TRUSTED"
    UNDECIDED: str = "UNDECIDED"
    DISTRUSTED: str = "DISTRUSTED"


# Note that while this is an "example", it is fully functional and can be used as-is.
class BTBVSessionManager(omemo.SessionManager):
    """
    Partial :class:`omemo.SessionManager` implementation with BTBV as its trust system.
    """

    async def _evaluate_custom_trust_level(self, device: omemo.DeviceInformation) -> omemo.TrustLevel:
        try:
            trust_level = BTBVTrustLevel(device.trust_level_name)
        except ValueError as e:
            raise omemo.UnknownTrustLevel(f"Unknown trust level name: {device.trust_level_name}") from e

        if trust_level is BTBVTrustLevel.TRUSTED or trust_level is BTBVTrustLevel.BLINDLY_TRUSTED:
            return omemo.TrustLevel.TRUSTED
        if trust_level is BTBVTrustLevel.UNDECIDED:
            return omemo.TrustLevel.UNDECIDED
        if trust_level is BTBVTrustLevel.DISTRUSTED:
            return omemo.TrustLevel.DISTRUSTED

        assert_never(trust_level)

    async def _make_trust_decision(
        self,
        undecided: FrozenSet[omemo.DeviceInformation],
        identifier: Optional[str]
    ) -> None:
        # For BTBV, affected JIDs can be separated into two pools: one pool of JIDs for which blind trust is
        # active, i.e. no manual verification was performed before, and one pool of JIDs to use manual trust
        # with instead.
        bare_jids = { device.bare_jid for device in undecided }

        blind_trust_bare_jids: Set[str] = set()
        manual_trust_bare_jids: Set[str] = set()

        # For each bare JID, decide whether blind trust applies
        for bare_jid in bare_jids:
            # Get all known devices belonging to the bare JID
            devices = await self.get_device_information(bare_jid)

            # If the trust levels of all devices correspond to those used by blind trust, blind trust applies.
            # Otherwise, fall back to manual trust.
            if all(BTBVTrustLevel(device.trust_level_name) in {
                BTBVTrustLevel.UNDECIDED,
                BTBVTrustLevel.BLINDLY_TRUSTED
            } for device in devices):
                blind_trust_bare_jids.add(bare_jid)
            else:
                manual_trust_bare_jids.add(bare_jid)

        # With the JIDs sorted into their respective pools, the undecided devices can be categorized too
        blindly_trusted_devices = { dev for dev in undecided if dev.bare_jid in blind_trust_bare_jids }
        manually_trusted_devices = { dev for dev in undecided if dev.bare_jid in manual_trust_bare_jids }

        # Blindly trust devices handled by blind trust
        if len(blindly_trusted_devices) > 0:
            for device in blindly_trusted_devices:
                await self.set_trust(
                    device.bare_jid,
                    device.identity_key,
                    BTBVTrustLevel.BLINDLY_TRUSTED.name
                )

            await self._devices_blindly_trusted(frozenset(blindly_trusted_devices), identifier)

        # Prompt the user for manual trust decisions on the devices handled by manual trust
        if len(manually_trusted_devices) > 0:
            await self._prompt_manual_trust(frozenset(manually_trusted_devices), identifier)

    async def _devices_blindly_trusted(
        self,
        blindly_trusted: FrozenSet[omemo.DeviceInformation],
        identifier: Optional[str]
    ) -> None:
        """
        Get notified about newly blindly trusted devices. This method is called automatically by
        :meth:`_make_trust_decision` whenever at least one device was blindly trusted. You can use this method
        for example to notify the user about the automated change in trust.

        Does nothing by default.

        Args:
            blindly_trusted: A set of devices that were blindly trusted.
            identifier: Forwarded from :meth:`_make_trust_decision`, refer to its documentation for details.
        """

    @abc.abstractmethod
    async def _prompt_manual_trust(
        self,
        manually_trusted: FrozenSet[omemo.DeviceInformation],
        identifier: Optional[str]
    ) -> None:
        """
        Prompt manual trust decision on a set of undecided identity keys. The trust decisions are expected to
        be persisted by calling :meth:`set_trust`.

        Args:
            manually_trusted: A set of devices whose trust has to be manually decided by the user.
            identifier: Forwarded from :meth:`_make_trust_decision`, refer to its documentation for details.

        Raises:
            TrustDecisionFailed: if for any reason the trust decision failed/could not be completed. Feel free
                to raise a subclass instead.

        Note:
            This is called when the encryption needs to know whether it is allowed to encrypt for these
            devices or not. When this method returns, all previously undecided trust levels should have been
            replaced by calling :meth:`set_trust` with a different trust level. If they are not replaced or
            still evaluate to the undecided trust level after the call, the encryption will fail with an
            exception. See :meth:`encrypt` for details.
        """
