from __future__ import absolute_import

from .promise import Promise
from .storage import Storage

def makeCallbackPromise(function, *args, **kwargs):
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

def wrap(is_async, attr):
    def _wrap(*args, **kwargs):
        if is_async:
            return makeCallbackPromise(attr, *args, **kwargs)
        else:
            return attr(None, *args, **kwargs)

    return _wrap

class StorageWrapper(object):
    def __init__(self, wrapped):
        self._wrapped = wrapped

    def __getattribute__(self, attr):
        if attr == "_wrapped":
            return super(StorageWrapper, self).__getattribute__(attr)

        if attr == "is_async":
            return self._wrapped.is_async

        return wrap(self.is_async, getattr(self._wrapped, attr))
