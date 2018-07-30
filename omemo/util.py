from __future__ import absolute_import

import os
import struct

DEVICE_ID_MIN = 1
DEVICE_ID_MAX = 2 ** 31 - 1

def generateDeviceID(blacklist = []):
    while True:
        device_id = struct.unpack(">L", os.urandom(4))[0]

        if device_id < DEVICE_ID_MIN or device_id > DEVICE_ID_MAX:
            continue

        if device_id in blacklist:
            continue

        return device_id
