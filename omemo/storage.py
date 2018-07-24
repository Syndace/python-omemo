"""
The interface used by the SessionManager to persist data between runs.

There are two possible ways to implement the Storage class: synchronous or asynchronous.

The mode is determined by the result of the is_async method.

If the implementation is asynchronous, the callback parameter is a function that takes
two arguments:
- success: True or False
- result: The result of the operation if success is True or the error if success is False

If the implementation is synchronous, the callback parameter is None.
"""

class Storage(object):
    def loadState(self, callback):
        """
        Read the state (the collection of keys for this device) and return None,
        if no state was stored previously.

        Return a dictionary containing:
        {
            "state": , # The X3DHDoubleRatchet state object
            "device_id": , # The device id
        }

        or None.
        """

        raise NotImplementedError

    def storeState(self, callback, state, device_id):
        """
        Store the state, overwriting the old state, if it exists.
        The state is an instance of X3DHDoubleRatchet,
        you probably want to pickle the whole object.
        """

        raise NotImplementedError

    def loadSession(self, callback, bare_jid, device_id):
        """
        Load a session with given bare_jid and device id or return None, if none exists.
        """

        raise NotImplementedError

    def storeSession(self, callback, bare_jid, device_id, session):
        """
        Store a session for given bare_jid and device id,
        overwriting the previous session, if it exists.

        The session is an instance of DoubleRatchet,
        you probably want to pickle the whole object.
        """

        raise NotImplementedError

    def loadActiveDevices(self, callback, bare_jid):
        """
        Load the list of active devices for a given bare_jid.

        An "active device" is a device, which is listed in the most recent version of
        the device list pep node.
        """

        raise NotImplementedError

    def loadInactiveDevices(self, callback, bare_jid):
        """
        Load the list of active devices for a given bare_jid.

        An "inactive device" is a device, which was listed in an older version of
        the device list pep node, but is NOT listed in the most recent version.
        """

        raise NotImplementedError

    def storeActiveDevices(self, callback, jid, devices):
        """
        Store the active devices for given jid, overwriting the old stored list,
        if it exists.
        """

        raise NotImplementedError

    def storeInactiveDevices(self, callback, bare_jid, devices):
        """
        Store the inactive devices for given bare_jid, overwriting the old stored list,
        if it exists.
        """

        raise NotImplementedError

    def isTrusted(self, callback, bare_jid, device):
        """
        Return, whether the given device of given bare_jid is trusted.
        """

        raise NotImplementedError

    @property
    def is_async(self):
        """
        Return, whether this implementation is asynchronous (uses the callback parameter).
        """

        raise NotImplementedError
