class Storage(object):
    """
    The interface used by the SessionManager to persist data between runs.

    There are two possible ways to implement the Storage class: synchronous or
    asynchronous.

    The mode is determined by the result of the is_async method.

    If the implementation is synchronous, the callback parameter is None.

    If the implementation is asynchronous, the callback parameter is a function that takes
    two arguments:
    - success: True or False
    - result: The result of the operation if success is True or the error if success is
        False

    Note:
    The SessionManager does caching to reduce the number of calls to a minimum. There
    should be no need to add caching or any other logic in here, just plain storing and
    loading.
    """

    def loadOwnData(self, callback):
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

    def storeOwnData(self, callback, own_bare_jid, own_device_id):
        """
        Store given own data, overwriting previously stored data.
        """

        raise NotImplementedError

    def loadState(self, callback):
        """
        Load the state.

        Return the stored structure or None, if no state was stored previously.
        """

        raise NotImplementedError

    def storeState(self, callback, state):
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

    def loadSession(self, callback, bare_jid, device_id):
        """
        Load a session with given bare_jid and device id.

        bare_jid is passed as a string, device_id as an integer.

        Return either the structure previously stored or None.
        """

        raise NotImplementedError

    def storeSession(self, callback, bare_jid, device_id, session):
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

    def deleteSession(self, callback, bare_jid, device_id):
        """
        Completely wipe the session associated with given bare_jid and device_id from the
        storage.

        bare_jid is passed as string, device_id as an integer.
        """

        raise NotImplementedError

    def loadActiveDevices(self, callback, bare_jid):
        """
        Load the list of active devices for a given bare_jid.

        An "active device" is a device, which is listed in the most recent version of
        the device list pep node.

        bare_jid is passed as a string, the result is expected to be a list of integers.
        """

        raise NotImplementedError

    def loadInactiveDevices(self, callback, bare_jid):
        """
        Load the list of inactive devices for a given bare_jid.

        An "inactive device" is a device, which was listed in an older version of
        the device list pep node, but is NOT listed in the most recent version.

        bare_jid is passed as a string, the result is expected to be a dict mapping from
        int to int, where the keys are device ids and the values are timestamps (seconds
        since epoch).
        """

        raise NotImplementedError

    def storeActiveDevices(self, callback, bare_jid, devices):
        """
        Store the active devices for given bare_jid, overwriting the old stored list,
        if it exists.

        bare_jid is passed as a string, devices as a list of integers.
        """

        raise NotImplementedError

    def storeInactiveDevices(self, callback, bare_jid, devices):
        """
        Store the inactive devices for given bare_jid, overwriting the old stored list,
        if it exists.

        bare_jid is passed as a string, devices as a dict mapping from int to int, where
        the keys are device ids and the values are timestamps (seconds since epoch).
        """

        raise NotImplementedError

    def storeTrust(self, callback, bare_jid, device_id, trust):
        """
        bare_jid: string
        device_id: int

        trust: {
            "key"     : string (Base64 encoded bytes),
            "trusted" : bool
        }
        """

        raise NotImplementedError

    def loadTrust(self, callback, bare_jid, device_id):
        """
        """

        raise NotImplementedError

    def listJIDs(self, callback):
        """
        List all bare jids that have associated device lists stored in the storage.
        It doesn't matter if the lists are empty or not.

        Return a list of strings.
        """

        raise NotImplementedError

    def deleteJID(self, callback, bare_jid):
        """
        Delete all data associated with given bare_jid. This includes the active and
        inactive devices, all sessions stored for that jid and all information about
        trusted keys.
        """

        raise NotImplementedError

    @property
    def is_async(self):
        """
        Return, whether this implementation is asynchronous.

        Read the introduction to this module above for details on what this value changes.
        """

        raise NotImplementedError
