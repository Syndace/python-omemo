import omemo

class InMemoryStorage(omemo.Storage):
    def __init__(self):
        self.__state = None
        self.__bundles = {}
        self.__sessions = {}
        self.__devices = {}

    def loadState(self):
        return self.__state

    def storeState(self, state, device_id):
        self.__state = {
            "state": state,
            "device_id": device_id
        }

    def loadSession(self, jid, device_id):
        return self.__sessions.get(jid, {}).get(device_id, None)

    def storeSession(self, jid, device_id, session):
        self.__sessions[jid] = self.__sessions.get(jid, {})
        self.__sessions[jid][device_id] = session

    def loadActiveDevices(self, jid):
        return self.__devices.get(jid, {}).get("active", [])

    def loadInactiveDevices(self, jid):
        return self.__devices.get(jid, {}).get("inactive", [])

    def storeActiveDevices(self, jid, devices):
        self.__devices[jid] = self.__devices.get(jid, {})
        self.__devices[jid]["active"] = devices

    def storeInactiveDevices(self, jid, devices):
        self.__devices[jid] = self.__devices.get(jid, {})
        self.__devices[jid]["inactive"] = devices

    def isTrusted(self, jid, device):
        return True
