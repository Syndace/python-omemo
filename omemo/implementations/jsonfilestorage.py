from ..storage import Storage

import base64
import hashlib
import json
import os
import shutil

class JSONFileStorage(Storage):
    def __init__(self, path):
        self.__path = path

    ####################################
    # JSON loading and dumping helpers #
    ####################################

    def __makePath(self, path_segments):
        # Add the .json extension
        path_segments[-1] += ".json"

        # Build the path in an OS-independent manner
        return os.path.join(self.__path, *path_segments)

    def __load(self, path_segments, default = None):
        try:
            with open(self.__makePath(path_segments), "rt") as f:
                # json.load can throw an exception if the JSON is malformed. This possible
                # exception is not caught here but rather passed to the user because
                # something is seriously wrong if the files contain malformed JSON.
                return json.load(f)
        except (OSError, IOError):
            return default

    def __dump(self, path_segments, value):
        # Prepare the path
        path = self.__makePath(path_segments)

        # Make sure the path exists
        try:
            os.makedirs(os.path.dirname(path))
        except OSError:
            pass

        # Dump the JSON.
        # Any exception raised here is not fixable, thus passed to the user.
        with open(path, "wt") as f:
            json.dump(value, f, allow_nan = False, indent = 4)

    def __remove(self, path_segments):
        try:
            os.remove(self.__makePath(path_segments))
        except OSError:
            pass

    def __rmdir(self, path_segments):
        shutil.rmtree(self.__makePath(path_segments), ignore_errors = True)

    @staticmethod
    def getHashForBareJID(bare_jid):
        digest = hashlib.sha256(bare_jid.encode("UTF-8")).digest()

        return base64.b32encode(digest).decode("US-ASCII")

    ###################################
    # Implementation of the interface #
    ###################################

    async def loadOwnData(self):
        return self.__load([ "own_data" ])

    async def storeOwnData(self, own_bare_jid, own_device_id):
        return self.__dump([ "own_data" ], {
            "own_bare_jid"  : own_bare_jid,
            "own_device_id" : own_device_id
        })

    async def loadState(self):
        return self.__load([ "state" ])

    async def storeState(self, state):
        return self.__dump([ "state" ], state)

    async def loadSession(self, bare_jid, device_id):
        bare_jid = self.__class__.getHashForBareJID(bare_jid)

        return self.__load([ bare_jid, "session_{}".format(device_id) ])

    async def storeSession(self, bare_jid, device_id, session):
        bare_jid = self.__class__.getHashForBareJID(bare_jid)

        return self.__dump([ bare_jid, "session_{}".format(device_id) ], session)

    async def deleteSession(self, bare_jid, device_id):
        bare_jid = self.__class__.getHashForBareJID(bare_jid)

        return self.__remove([ bare_jid, "session_{}".format(device_id) ])

    async def loadActiveDevices(self, bare_jid):
        bare_jid = self.__class__.getHashForBareJID(bare_jid)

        return set(self.__load([ bare_jid, "active_devices" ], []))

    async def loadInactiveDevices(self, bare_jid):
        bare_jid = self.__class__.getHashForBareJID(bare_jid)

        result = self.__load([ bare_jid, "inactive_devices" ], {})

        return { int(device): timestamp for device, timestamp in result.items() }

    async def storeActiveDevices(self, bare_jid, devices):
        bare_jid = self.__class__.getHashForBareJID(bare_jid)

        return self.__dump([ bare_jid, "active_devices" ], list(devices))

    async def storeInactiveDevices(self, bare_jid, devices):
        bare_jid = self.__class__.getHashForBareJID(bare_jid)

        return self.__dump([ bare_jid, "inactive_devices" ], devices)

    async def loadTrust(self, bare_jid, device_id):
        bare_jid = self.__class__.getHashForBareJID(bare_jid)

        return self.__load([ bare_jid, "trust_{}".format(device_id) ])

    async def storeTrust(self, bare_jid, device_id, trust):
        bare_jid = self.__class__.getHashForBareJID(bare_jid)

        return self.__dump([ bare_jid, "trust_{}".format(device_id) ], trust)

    async def listJIDs(self):
        result = []

        for entry in os.listdir(self.__path):
            if os.path.isdir(os.path.join(self.__path, entry)):
                result.append(entry)

        return result

    async def deleteJID(self, bare_jid):
        bare_jid = self.__class__.getHashForBareJID(bare_jid)

        return self.__rmdir([ bare_jid ])
