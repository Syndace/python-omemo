import omemo

import copy
import json

class AsyncInMemoryStorage(omemo.Storage):
    def __init__(self):
        self.__state = None
        self.__own_data_set  = False
        self.__own_bare_jid  = None
        self.__own_device_id = None
        self.__sessions = {}
        self.__devices = {}
        self.__trust = {}

    def dump(self):
        return copy.deepcopy({
            "state"    : self.__state,
            "sessions" : self.__sessions,
            "devices"  : self.__devices
        })

    def loadOwnData(self, callback):
        callback(True, {
            "own_bare_jid"  : self.__own_bare_jid,
            "own_device_id" : self.__own_device_id
        } if self.__own_data_set else None)

    def storeOwnData(self, callback, own_bare_jid, own_device_id):
        self.__own_data_set  = True
        self.__own_bare_jid  = own_bare_jid
        self.__own_device_id = own_device_id

        callback(True, None)

    def loadState(self, callback):
        callback(True, None if self.__state == None else json.loads(self.__state))

    def storeState(self, callback, state):
        self.__state = json.dumps(state) # Woohoo! The object is json serializable!

        callback(True, None)

    def loadSession(self, callback, bare_jid, device_id):
        callback(True, self.__sessions.get(bare_jid, {}).get(device_id, None))

    def storeSession(self, callback, bare_jid, device_id, session):
        self.__sessions[bare_jid] = self.__sessions.get(bare_jid, {})
        self.__sessions[bare_jid][device_id] = session

        callback(True, None)

    def deleteSession(self, callback, bare_jid, device_id):
        self.__sessions[bare_jid] = self.__sessions.get(bare_jid, {})
        self.__sessions[bare_jid].pop(device_id, None)

        callback(True, None)

    def loadActiveDevices(self, callback, bare_jid):
        callback(True, self.__devices.get(bare_jid, {}).get("active", []))

    def loadInactiveDevices(self, callback, bare_jid):
        callback(True, self.__devices.get(bare_jid, {}).get("inactive", {}))

    def storeActiveDevices(self, callback, bare_jid, devices):
        self.__devices[bare_jid] = self.__devices.get(bare_jid, {})
        self.__devices[bare_jid]["active"] = devices

        callback(True, None)

    def storeInactiveDevices(self, callback, bare_jid, devices):
        self.__devices[bare_jid] = self.__devices.get(bare_jid, {})
        self.__devices[bare_jid]["inactive"] = devices

        callback(True, None)

    def storeTrust(self, callback, bare_jid, device_id, trust):
        self.__trust[bare_jid] = self.__trust.get(bare_jid, {})
        self.__trust[bare_jid][device_id] = trust

        callback(True, None)

    def loadTrust(self, callback, bare_jid, device_id):
        callback(True, self.__trust.get(bare_jid, {}).get(device_id, None))

    def listJIDs(self, callback):
        callback(True, list(self.__devices.keys()))

    def deleteJID(self, callback, bare_jid):
        self.__devices.pop(bare_jid, None)
        self.__sessions.pop(bare_jid, None)

        callback(True, None)

    @property
    def is_async(self):
        return True
