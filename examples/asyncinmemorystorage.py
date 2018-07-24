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

    def loadSession(self, callback, bare_jid, device_id):
        callback(True, self.__sessions.get(bare_jid, {}).get(device_id, None))

    def storeSession(self, callback, bare_jid, device_id, session):
        self.__sessions[bare_jid] = self.__sessions.get(bare_jid, {})
        self.__sessions[bare_jid][device_id] = session

        callback(True, None)

    def loadActiveDevices(self, callback, bare_jid):
        callback(True, self.__devices.get(bare_jid, {}).get("active", []))

    def loadInactiveDevices(self, callback, bare_jid):
        callback(True, self.__devices.get(bare_jid, {}).get("inactive", []))

    def storeActiveDevices(self, callback, bare_jid, devices):
        self.__devices[bare_jid] = self.__devices.get(bare_jid, {})
        self.__devices[bare_jid]["active"] = devices

        callback(True, None)

    def storeInactiveDevices(self, callback, bare_jid, devices):
        self.__devices[bare_jid] = self.__devices.get(bare_jid, {})
        self.__devices[bare_jid]["inactive"] = devices

        callback(True, None)

    def isTrusted(self, callback, bare_jid, device):
        callback(True, True)

    @property
    def is_async(self):
        return True
