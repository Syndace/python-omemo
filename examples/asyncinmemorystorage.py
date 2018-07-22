import omemo

class AsyncInMemoryStorage(omemo.Storage):
    def __init__(self):
        self.__state = None
        self.__bundles = {}
        self.__sessions = {}
        self.__devices = {}

    def loadState(self, callback):
        callback(True, self.__state)

    def storeState(self, callback, state, device_id):
        self.__state = {
            "state": state,
            "device_id": device_id
        }

        callback(True, None)

    def loadSession(self, callback, jid, device_id):
        callback(True, self.__sessions.get(jid, {}).get(device_id, None))

    def storeSession(self, callback, jid, device_id, session):
        self.__sessions[jid] = self.__sessions.get(jid, {})
        self.__sessions[jid][device_id] = session

        callback(True, None)

    def loadActiveDevices(self, callback, jid):
        callback(True, self.__devices.get(jid, {}).get("active", []))

    def loadInactiveDevices(self, callback, jid):
        callback(True, self.__devices.get(jid, {}).get("inactive", []))

    def storeActiveDevices(self, callback, jid, devices):
        self.__devices[jid] = self.__devices.get(jid, {})
        self.__devices[jid]["active"] = devices

        callback(True, None)

    def storeInactiveDevices(self, callback, jid, devices):
        self.__devices[jid] = self.__devices.get(jid, {})
        self.__devices[jid]["inactive"] = devices

        callback(True, None)

    def isTrusted(self, callback, jid, device):
        callback(True, True)

    @property
    def is_async(self):
        return True
