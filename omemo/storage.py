class Storage(object):
    def loadState(self):
        """
        Read the state (the collection of keys for this device) and return None, if no state was stored previously.
        """

        raise NotImplementedError

    def storeState(self, state):
        """
        Store the state, overwriting the old state, if it exists.
        The state is an instance of X3DHDoubleRatchet, you probably want to pickle the whole object.
        """

        raise NotImplementedError

    def loadBundle(self, jid, device_id):
        """
        Load the bundle for given jid and device id and return None if no bundle was stored for this jid and device id previously.
        """

        raise NotImplementedError


    def storeBundle(self, jid, device_id, bundle):
        """
        Store this bundle for given jid and device id, overwriting old bundles.
        The bundle is an instance of ExtendedPublicBundle, which can easily be serialized into a python dictionary and stored in various ways, e.g. using json.
        """

        raise NotImplementedError

    def listDevices(self, jid):
        """
        Return a list of all known devices for given jid.
        You probably want to do this by looking at the list of bundles stored for this jid and extracting the device ids.
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
