import asyncio

class Storage:
    """
    The interface used by the SessionManager to persist data between runs.

    Note:
    The SessionManager does caching to reduce the number of calls to a minimum. There
    should be no need to add caching or any other logic in here, just plain storing and
    loading.
    """

    async def loadOwnData(self):
        """
        Load the own data.

        Return a dictionary of following structure:
        {
            "own_bare_jid"  : string,
            "own_device_id" : int
        }

        or None, if no own data was stored previously.
        """

        raise NotImplementedError

    async def storeOwnData(self, own_bare_jid, own_device_id):
        """
        Store given own data, overwriting previously stored data.
        """

        raise NotImplementedError

    async def loadState(self):
        """
        Load the state.

        Return the stored structure or None, if no state was stored previously.
        """

        raise NotImplementedError

    async def storeState(self, state):
        """
        Store the state, overwriting the old state, if it exists.

        state is passed as a serializable object, that means it consist of a combination
        of the following types:
        - dictionaries
        - lists
        - strings
        - integers
        - floats
        - booleans
        - None

        You can dump this object using for example the json module.

        For more information on how the state object is structured, look at the
        omemo.X3DHDoubleRatchet.serialize method.
        """

        raise NotImplementedError

    async def loadSession(self, bare_jid, device_id):
        """
        Load a session with given bare_jid and device id.

        bare_jid is passed as a string, device_id as an integer.

        Return either the structure previously stored or None.
        """

        raise NotImplementedError

    async def loadSessions(self, bare_jid, device_ids):
        """
        Return a dict containing the session for each device id. By default, this method
        calls loadSession for each device id.
        """

        return dict(zip(device_ids, await asyncio.gather(*[
            self.loadSession(bare_jid, device_id) for device_id in device_ids
        ])))

    async def storeSession(self, bare_jid, device_id, session):
        """
        Store a session for given bare_jid and device id, overwriting the previous
        session, if it exists.

        bare_jid is passed as string, device_id as an integer.

        session is passed as a serializable object, that means it consist of a combination
        of the following types:
        - dictionaries
        - lists
        - strings
        - integers
        - floats
        - booleans
        - None

        You can dump this object using for example the json module.
        """

        raise NotImplementedError

    async def deleteSession(self, bare_jid, device_id):
        """
        Completely wipe the session associated with given bare_jid and device_id from the
        storage.

        bare_jid is passed as string, device_id as an integer.
        """

        raise NotImplementedError

    async def loadActiveDevices(self, bare_jid):
        """
        Load the list of active devices for a given bare_jid.

        An "active device" is a device, which is listed in the most recent version of
        the device list pep node.

        bare_jid is passed as a string, the result is expected to be a list of integers.
        """

        raise NotImplementedError

    async def loadInactiveDevices(self, bare_jid):
        """
        Load the list of inactive devices for a given bare_jid.

        An "inactive device" is a device, which was listed in an older version of
        the device list pep node, but is NOT listed in the most recent version.

        bare_jid is passed as a string, the result is expected to be a dict mapping from
        int to int, where the keys are device ids and the values are timestamps (seconds
        since epoch).
        """

        raise NotImplementedError

    async def storeActiveDevices(self, bare_jid, devices):
        """
        Store the active devices for given bare_jid, overwriting the old stored list,
        if it exists.

        bare_jid is passed as a string, devices as a list of integers.
        """

        raise NotImplementedError

    async def storeInactiveDevices(self, bare_jid, devices):
        """
        Store the inactive devices for given bare_jid, overwriting the old stored list,
        if it exists.

        bare_jid is passed as a string, devices as a dict mapping from int to int, where
        the keys are device ids and the values are timestamps (seconds since epoch).
        """

        raise NotImplementedError

    async def loadTrust(self, bare_jid, device_id):
        """
        """

        raise NotImplementedError

    async def loadTrusts(self, bare_jid, device_ids):
        """
        Return a dict containing the trust status for each device id. By default, this
        method calls loadTrust for each device id.
        """

        return dict(zip(device_ids, await asyncio.gather(*[
            self.loadTrust(bare_jid, device_id) for device_id in device_ids
        ])))

    async def storeTrust(self, bare_jid, device_id, trust):
        """
        bare_jid: string
        device_id: int

        trust: None or {
            "key"     : string (Base64 encoded bytes),
            "trusted" : bool
        }
        """

        raise NotImplementedError

    async def listJIDs(self):
        """
        List all bare jids that have associated device lists stored in the storage.
        It doesn't matter if the lists are empty or not.

        Return a list of strings.
        """

        raise NotImplementedError

    async def deleteJID(self, bare_jid):
        """
        Delete all data associated with given bare_jid. This includes the active and
        inactive devices, all sessions stored for that jid and all information about
        trusted keys.
        """

        raise NotImplementedError
