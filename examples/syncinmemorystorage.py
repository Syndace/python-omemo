import omemo

class SyncInMemoryStorage(omemo.Storage):
    def __init__(self):
        self.__state = None
        self.__bundles = {}
        self.__sessions = {}
        self.__devices = {}

    def loadState(self, callback):
        return self.__state

    def storeState(self, callback, state, device_id):
        self.__state = {
            "state": state,
            "device_id": device_id
        }

    def loadSession(self, callback, jid, device_id):
        return self.__sessions.get(jid, {}).get(device_id, None)

    def storeSession(self, callback, jid, device_id, session):
        self.__sessions[jid] = self.__sessions.get(jid, {})
        self.__sessions[jid][device_id] = session

    def loadActiveDevices(self, callback, jid):
        return self.__devices.get(jid, {}).get("active", [])

    def loadInactiveDevices(self, callback, jid):
        return self.__devices.get(jid, {}).get("inactive", [])

    def storeActiveDevices(self, callback, jid, devices):
        self.__devices[jid] = self.__devices.get(jid, {})
        self.__devices[jid]["active"] = devices

    def storeInactiveDevices(self, callback, jid, devices):
        self.__devices[jid] = self.__devices.get(jid, {})
        self.__devices[jid]["inactive"] = devices

    def isTrusted(self, callback, jid, device):
        return True

    @property
    def is_async(self):
        return False
