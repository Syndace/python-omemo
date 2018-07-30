from __future__ import absolute_import

import functools
import types

class ReturnValueException(Exception):
    def __init__(self, value):
        self.__value = value

    @property
    def value(self):
        return self.__value

class RejectedException(Exception):
    def __init__(self, reason):
        self.__reason = reason
    
    def __eq__(self, other):
        if isinstance(other, RejectedException):
            return self.__reason == other.reason

        return False

    def __hash__(self):
        return hash(self.__reason)

    @property
    def reason(self):
        return self.__reason

class InvalidCoroutineException(Exception):
    def __init__(self, reason):
        self.__reason = reason
    
    def __eq__(self, other):
        if isinstance(other, InvalidCoroutineException):
            return self.__reason == other.reason

        return False

    def __hash__(self):
        return hash(self.__reason)

    @property
    def reason(self):
        return self.__reason

class Promise(object):
    PENDING   = "PENDING"
    FULFILLED = "FULFILLED"
    REJECTED  = "REJECTED"

    def __init__(self, code):
        self.__state  = Promise.PENDING
        self.__value  = None
        self.__reason = None

        self.__onfulfilled = []
        self.__onrejected  = []

        try:
            code(self.__resolve, self.__reject)
        except BaseException as e:
            self.__reject(e)

    def __resolve(self, value):
        if self.__state == Promise.PENDING:
            self.__value = value
            self.__state = Promise.FULFILLED

            while len(self.__onfulfilled) > 0:
                listener = self.__onfulfilled.pop(0)
                listener(self.__value)

    def __reject(self, reason):
        if self.__state == Promise.PENDING:
            self.__reason = reason
            self.__state  = Promise.REJECTED

            while len(self.__onrejected) > 0:
                listener = self.__onrejected.pop(0)
                listener(self.__reason)

    def then(self, onfulfilled, onrejected):
        if callable(onfulfilled):
            if self.__state == Promise.PENDING:
                self.__onfulfilled.append(onfulfilled)
            
            if self.__state == Promise.FULFILLED:
                onfulfilled(self.__value)

        if callable(onrejected):
            if self.__state == Promise.PENDING:
                self.__onrejected.append(onrejected)
            
            if self.__state == Promise.REJECTED:
                onrejected(self.__reason)

    @property
    def done(self):
        return not self.__state == Promise.PENDING

    @property
    def fulfilled(self):
        return self.__state == Promise.FULFILLED

    @property
    def rejected(self):
        return self.__state == Promise.REJECTED

    def __str__(self):
        if self.__state == Promise.PENDING:
            return "Pending Promise object"

        if self.__state == Promise.FULFILLED:
            return "Fulfilled Promise object with value: " + str(self.__value)

        if self.__state == Promise.REJECTED:
            return "Rejected Promise object with reason: " + str(self.__reason)

    @property
    def state(self):
        return self.__state

    @property
    def value(self):
        return self.__value

    @property
    def reason(self):
        return self.__reason

    @classmethod
    def resolve(cls, value):
        return cls(lambda resolve, reject: resolve(value))

    @classmethod
    def reject(cls, reason):
        return cls(lambda resolve, reject: reject(reason))

def returnValue(value):
    """
    In Python 2 we are not allowed to return from a generator function.

    Instead, we have to raise the StopIteration exceptions ourselves to return from the
    coroutine.

    Python 3.7 for some fucking reason changed it so you can't raise a StopIteration
    exception yourself. Really fucking great idea. Let's make it harder every fucking
    version to write software for Python 2 AND 3.

    For this awesome reason, we don't raise a StopIteration exception but a self-made
    exception called ReturnValueException.

    I don't know, the whole asyncio thing to me seems like some cancer that slowly makes
    Python less and less usable.

    It was fine, when we just had generators and yield.
    """

    raise ReturnValueException(value)

def coroutine(f):
    """
    Implementation of a coroutine.

    Use as a decorator:
    @coroutine
    def foo():
        result = yield somePromise

    The function passed should be a generator yielding instances of the Promise class
    (or compatible).
    The coroutine waits for the Promise to resolve and sends the result (or the error)
    back into the generator function.
    This simulates sequential execution which in reality can be asynchonous.
    """

    @functools.wraps(f)
    def _coroutine(*args, **kwargs):
        def _resolver(resolve, reject):
            try:
                generator = f(*args, **kwargs)
            except BaseException as e:
                # Special case for a function that throws immediately
                reject(e)
            else:
                # Special case for a function that returns immediately
                if not isinstance(generator, types.GeneratorType):
                    resolve(generator)
                else:
                    def _step(previous, previous_type):
                        element = None

                        try:
                            if previous_type == None:
                                element = next(generator)
                            elif previous_type:
                                element = generator.send(previous)
                            else:
                                if not isinstance(previous, BaseException):
                                    previous = RejectedException(previous)

                                element = generator.throw(previous)
                        except StopIteration as e:
                            resolve(getattr(e, "value", None))
                        except ReturnValueException as e:
                            resolve(e.value)
                        except BaseException as e:
                            reject(e)
                        else:
                            try:
                                element.then(
                                    lambda value  : _step(value, True),
                                    lambda reason : _step(reason, False)
                                )
                            except AttributeError:
                                reject(InvalidCoroutineException(element))

                    _step(None, None)

        return Promise(_resolver)

    return _coroutine

def no_coroutine(f):
    """
    This is not a coroutine ;)

    Use as a decorator:
    @no_coroutine
    def foo():
        five = yield 5
        print(yield "hello")

    The function passed should be a generator yielding whatever you feel like.
    The yielded values instantly get passed back into the generator.
    It's basically the same as if you didn't use yield at all.
    The example above is equivalent to:
    def foo():
        five = 5
        print("hello")

    Why?
    This is the counterpart to coroutine used by maybe_coroutine below.
    """

    @functools.wraps(f)
    def _no_coroutine(*args, **kwargs):
        generator = f(*args, **kwargs)

        # Special case for a function that returns immediately
        if not isinstance(generator, types.GeneratorType):
            return generator

        def _step(previous, first):
            element = None

            try:
                if first:
                    element = next(generator)
                else:
                    element = generator.send(previous)
            except StopIteration as e:
                return getattr(e, "value", None)
            except ReturnValueException as e:
                return e.value
            else:
                return _step(element, False)

        return _step(None, True)

    return _no_coroutine

def maybe_coroutine(decide):
    """
    Either be a coroutine or not.

    Use as a decorator:
    @maybe_coroutine(lambda maybeAPromise: return isinstance(maybeAPromise, Promise))
    def foo(maybeAPromise):
        result = yield maybeAPromise
        print("hello")
        return result

    The function passed should be a generator yielding either only Promises or whatever
    you feel like.
    The decide parameter must be a function which gets called with the same parameters as
    the function to decide whether this is a coroutine or not.
    Using this it is possible to either make the function a coroutine or not based on a
    parameter to the function call.
    Let's explain the example above:

    # If the maybeAPromise is an instance of Promise,
    # we want the foo function to act as a coroutine.
    # If the maybeAPromise is not an instance of Promise,
    # we want the foo function to act like any other normal synchronous function.
    @maybe_coroutine(lambda maybeAPromise: return isinstance(maybeAPromise, Promise))
    def foo(maybeAPromise):
        # If isinstance(maybeAPromise, Promise), foo behaves like a coroutine,
        # thus maybeAPromise will get resolved asynchronously and the result will be
        # pushed back here.
        # Otherwise, foo behaves like no_coroutine,
        # just pushing the exact value of maybeAPromise back into the generator.
        result = yield maybeAPromise
        print("hello")
        return result
    """

    def _maybe_coroutine(f):
        @functools.wraps(f)
        def __maybe_coroutine(*args, **kwargs):
            if decide(*args, **kwargs):
                return coroutine(f)(*args, **kwargs)
            else:
                return no_coroutine(f)(*args, **kwargs)
        return __maybe_coroutine
    return _maybe_coroutine
