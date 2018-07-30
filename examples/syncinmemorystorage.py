import omemo

import json

class SyncInMemoryStorage(omemo.Storage):
    def __init__(self):
        self.__state = None
        self.__own_data_set  = False
        self.__own_bare_jid  = None
        self.__own_device_id = None
        self.__sessions = {}
        self.__devices = {}

    def loadOwnData(self, callback):
        return ({
            "own_bare_jid"  : self.__own_bare_jid,
            "own_device_id" : self.__own_device_id
        } if self.__own_data_set else None)

    def storeOwnData(self, callback, own_bare_jid, own_device_id):
        self.__own_data_set  = True
        self.__own_bare_jid  = own_bare_jid
        self.__own_device_id = own_device_id

    def loadState(self, callback):
        return None if self.__state == None else json.loads(self.__state)

    def storeState(self, callback, state):
        self.__state = json.dumps(state) # Woohoo! The object is json serializable!

    def loadSession(self, callback, bare_jid, device_id):
        return self.__sessions.get(bare_jid, {}).get(device_id, None)

    def storeSession(self, callback, bare_jid, device_id, session):
        self.__sessions[bare_jid] = self.__sessions.get(bare_jid, {})
        self.__sessions[bare_jid][device_id] = session

    def loadActiveDevices(self, callback, bare_jid):
        return self.__devices.get(bare_jid, {}).get("active", [])

    def loadInactiveDevices(self, callback, bare_jid):
        return self.__devices.get(bare_jid, {}).get("inactive", [])

    def storeActiveDevices(self, callback, bare_jid, devices):
        self.__devices[bare_jid] = self.__devices.get(bare_jid, {})
        self.__devices[bare_jid]["active"] = devices

    def storeInactiveDevices(self, callback, bare_jid, devices):
        self.__devices[bare_jid] = self.__devices.get(bare_jid, {})
        self.__devices[bare_jid]["inactive"] = devices

    def isTrusted(self, callback, bare_jid, device):
        return True

    @property
    def is_async(self):
        return False
