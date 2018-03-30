class Storage(object):
    def loadState(self):
        """
        Read the state (the collection of keys for this device) and return None, if no state was stored previously.

        Return a dictionary containing:
        {
            "state": , # The X3DHDoubleRatchet state object
            "device_id": , # The device id
        }

        or None.
        """

        raise NotImplementedError

    def storeState(self, state, device_id):
        """
        Store the state, overwriting the old state, if it exists.
        The state is an instance of X3DHDoubleRatchet, you probably want to pickle the whole object.
        """

        raise NotImplementedError

    def loadSession(self, jid, device_id):
        """
        Load a session with given jid and device id or return None, if none exists.
        """

        raise NotImplementedError

    def storeSession(self, jid, device_id, session):
        """
        Store a session for given jid and device id, overwriting the previous session, if it exists.
        The session is an instance of DoubleRatchet, you probably want to pickle the whole object.
        """

        raise NotImplementedError

    def loadActiveDevices(self, jid):
        """
        Load the list of active devices for a given jid.

        An "active device" is a device, which is listed in the most recent version of the device list pep node.
        """

        raise NotImplementedError

    def loadInactiveDevices(self, jid):
        """
        Load the list of active devices for a given jid.

        An "inactive device" is a device, which was listed in an older version of the device list pep node,
        but is NOT listed in the most recent version.
        """

        raise NotImplementedError

    def storeActiveDevices(self, jid, devices):
        """
        Store the active devices for given jid, overwriting the old stored list, if it exists.
        """

        raise NotImplementedError

    def storeInactiveDevices(self, jid, devices):
        """
        Store the inactive devices for given jid, overwriting the old stored list, if it exists.
        """

        raise NotImplementedError
