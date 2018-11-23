from __future__ import absolute_import

import asyncio

from .promise import Promise
from .sessionmanager import SessionManager

def wrap(attr):
    def _wrap(*args, **kwargs):
        result = attr(*args, **kwargs)

        if isinstance(result, Promise):
            future = asyncio.Future()
            result.then(future.set_result, future.set_exception)
            return future
        else:
            return result

    return _wrap

class SessionManagerAsyncIO(SessionManager):
    @classmethod
    def create(cls, *args, **kwargs):
        result = super(SessionManagerAsyncIO, cls).create(*args, **kwargs)

        if isinstance(result, Promise):
            future = asyncio.Future()
            result.then(future.set_result, future.set_exception)
            return future
        else:
            return result

    def __getattribute__(self, attr_name):
        attr = super(SessionManagerAsyncIO, self).__getattribute__(attr_name)

        print("Requested:", attr_name)

        if attr_name in [
            "encryptMessage",
            "encryptKeyTransportMessage",
            "buildSession",
            "decryptMessage",
            "newDeviceList",
            "getDevices",
            "public_bundle",
            "republish_bundle"
        ]:
            return wrap(attr)

        return attr
