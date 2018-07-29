from ..exceptions import InvalidFieldError, VersionException

CURRENT_MAJOR_VERSION = 3
CURRENT_MINOR_VERSION = 3
KEY_TYPE_25519 = 5

def toBytes(data):
    def toInt(x):
        try:
            return ord(x)
        except TypeError:
            return x

    try:
        return [ toInt(x) for x in data ]
    except TypeError:
        return data

def bytesToString(data):
    return bytes(bytearray(data))

def checkVersion(data):
    try:
        version = ord(data[0])
    except TypeError:
        version = data[0]

    major_version = (version >> 4) & 0x0F
    minor_version = (version >> 0) & 0x0F

    if major_version < CURRENT_MAJOR_VERSION or minor_version < CURRENT_MINOR_VERSION:
        raise VersionException("Legacy version detected")

    if major_version > CURRENT_MAJOR_VERSION or minor_version > CURRENT_MINOR_VERSION:
        raise VersionException("Newer/unknown version detected")

    return data[1:]

def prependVersion(data):
    return bytes(bytearray([ CURRENT_MAJOR_VERSION << 4 | CURRENT_MINOR_VERSION ])) + data

def decodePublicKey(key):
    if len(key) != 33:
        raise InvalidFieldError("The key field must contain 33 bytes of data")

    try:
        key_type = ord(key[0])
    except TypeError:
        key_type = key[0]

    if key_type != KEY_TYPE_25519:
        raise InvalidFieldError("Unknown key type")

    return key[1:]

def encodePublicKey(key):
    return bytes(bytearray([ KEY_TYPE_25519 ])) + key
