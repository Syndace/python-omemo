from .promise import Promise
from .storage import Storage

def makeCBPromise(function, *args, **kwargs):
    """
    Take a function that reports its result using a callback and return a Promise that
    listenes for this callback.

    The function must accept a callback as its first parameter.
    The callback must take two arguments:
    - success : True or False
    - result  : The result of the operation if success is True or the error otherwise.
    """

    def _resolver(resolve, reject):
        function(
            lambda success, result: resolve(result) if success else reject(result),
            *args,
            **kwargs
        )

    return Promise(_resolver)

class StorageWrapper(Storage):
    def __init__(self, wrapped):
        self.__wrapped = wrapped

    def loadState(self, *args, **kwargs):
        if self.__wrapped.is_async:
            return makeCBPromise(self.__wrapped.loadState, *args, **kwargs)
        else:
            return self.__wrapped.loadState(None, *args, **kwargs)

    def storeState(self, *args, **kwargs):
        if self.__wrapped.is_async:
            return makeCBPromise(self.__wrapped.storeState, *args, **kwargs)
        else:
            return self.__wrapped.storeState(None, *args, **kwargs)

    def loadSession(self, *args, **kwargs):
        if self.__wrapped.is_async:
            return makeCBPromise(self.__wrapped.loadSession, *args, **kwargs)
        else:
            return self.__wrapped.loadSession(None, *args, **kwargs)

    def storeSession(self, *args, **kwargs):
        if self.__wrapped.is_async:
            return makeCBPromise(self.__wrapped.storeSession, *args, **kwargs)
        else:
            return self.__wrapped.storeSession(None, *args, **kwargs)

    def loadActiveDevices(self, *args, **kwargs):
        if self.__wrapped.is_async:
            return makeCBPromise(self.__wrapped.loadActiveDevices, *args, **kwargs)
        else:
            return self.__wrapped.loadActiveDevices(None, *args, **kwargs)

    def loadInactiveDevices(self, *args, **kwargs):
        if self.__wrapped.is_async:
            return makeCBPromise(self.__wrapped.loadInactiveDevices, *args, **kwargs)
        else:
            return self.__wrapped.loadInactiveDevices(None, *args, **kwargs)

    def storeActiveDevices(self, *args, **kwargs):
        if self.__wrapped.is_async:
            return makeCBPromise(self.__wrapped.storeActiveDevices, *args, **kwargs)
        else:
            return self.__wrapped.storeActiveDevices(None, *args, **kwargs)

    def storeInactiveDevices(self, *args, **kwargs):
        if self.__wrapped.is_async:
            return makeCBPromise(self.__wrapped.storeInactiveDevices, *args, **kwargs)
        else:
            return self.__wrapped.storeInactiveDevices(None, *args, **kwargs)

    def isTrusted(self, *args, **kwargs):
        if self.__wrapped.is_async:
            return makeCBPromise(self.__wrapped.isTrusted, *args, **kwargs)
        else:
            return self.__wrapped.isTrusted(None, *args, **kwargs)

    @property
    def is_async(self):
        return self.__wrapped.is_async
