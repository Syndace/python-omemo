import omemo

import copy
import json

class InMemoryStorage(omemo.Storage):
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

    async def loadOwnData(self):
        return ({
            "own_bare_jid"  : self.__own_bare_jid,
            "own_device_id" : self.__own_device_id
        } if self.__own_data_set else None)

    async def storeOwnData(self, own_bare_jid, own_device_id):
        self.__own_data_set  = True
        self.__own_bare_jid  = own_bare_jid
        self.__own_device_id = own_device_id

    async def loadState(self):
        return None if self.__state == None else json.loads(self.__state)

    async def storeState(self, state):
        self.__state = json.dumps(state) # Woohoo! The object is json serializable!

    async def loadSession(self, bare_jid, device_id):
        return self.__sessions.get(bare_jid, {}).get(device_id, None)

    async def storeSession(self, bare_jid, device_id, session):
        self.__sessions[bare_jid] = self.__sessions.get(bare_jid, {})
        self.__sessions[bare_jid][device_id] = session

    async def deleteSession(self, bare_jid, device_id):
        self.__sessions[bare_jid] = self.__sessions.get(bare_jid, {})
        self.__sessions[bare_jid].pop(device_id, None)

    async def loadActiveDevices(self, bare_jid):
        return self.__devices.get(bare_jid, {}).get("active", [])

    async def loadInactiveDevices(self, bare_jid):
        return self.__devices.get(bare_jid, {}).get("inactive", {})

    async def storeActiveDevices(self, bare_jid, devices):
        self.__devices[bare_jid] = self.__devices.get(bare_jid, {})
        self.__devices[bare_jid]["active"] = devices

    async def storeInactiveDevices(self, bare_jid, devices):
        self.__devices[bare_jid] = self.__devices.get(bare_jid, {})
        self.__devices[bare_jid]["inactive"] = devices

    async def storeTrust(self, bare_jid, device_id, trust):
        self.__trust[bare_jid] = self.__trust.get(bare_jid, {})
        self.__trust[bare_jid][device_id] = trust

    async def loadTrust(self, bare_jid, device_id):
        return self.__trust.get(bare_jid, {}).get(device_id, None)

    async def listJIDs(self):
        return list(self.__devices.keys())

    async def deleteJID(self, bare_jid):
        self.__devices.pop(bare_jid, None)
        self.__sessions.pop(bare_jid, None)
