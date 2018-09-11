import pytest

import logging

logging.basicConfig(level = logging.DEBUG)

import omemo
from omemo import SessionManager
from omemo.exceptions import *

from asyncinmemorystorage import AsyncInMemoryStorage
from syncinmemorystorage  import SyncInMemoryStorage

from deletingotpkpolicy import DeletingOTPKPolicy
from keepingotpkpolicy  import KeepingOTPKPolicy

from example_data import *
from example_data import (
    ALICE_BARE_JID   as A_JID,
    ALICE_DEVICE_ID  as A_DID,
    ALICE_DEVICE_IDS as A_DIDS
)

def assertPromiseFulfilled(promise):
    assert isinstance(promise, omemo.promise.Promise)
    assert promise.fulfilled
    return promise.value

def assertPromiseRejected(promise):
    assert isinstance(promise, omemo.promise.Promise)
    assert promise.rejected
    return promise.reason

def getDevices(sm_sync, sm_async, jid, inactive, active):
    inactive = set(inactive)
    active   = set(active)

    devices_sync  = sm_sync.getDevices(jid)
    devices_async = assertPromiseFulfilled(sm_async.getDevices(jid))

    assert devices_sync ["inactive"] == inactive
    assert devices_async["inactive"] == inactive
    assert devices_sync ["active"]   == active
    assert devices_async["active"]   == active

def newDeviceList(sm_sync, sm_async, devices, jid):
    sm_sync.newDeviceList(devices, jid)
    assertPromiseFulfilled(sm_async.newDeviceList(devices, jid))

def createSessionManagers():
    st_sync  = SyncInMemoryStorage()
    st_async = AsyncInMemoryStorage()

    sm_sync  = SessionManager.create(st_sync,  DeletingOTPKPolicy, A_JID, A_DID)
    sm_async = SessionManager.create(st_async, DeletingOTPKPolicy, A_JID, A_DID)

    assert isinstance(sm_sync, SessionManager)
    assert isinstance(assertPromiseFulfilled(sm_async), SessionManager)

    return st_sync, sm_sync, st_async, sm_async.value

def test_create_supplyInfo():
    createSessionManagers()

def test_create_missingInfo():
    st_sync  = SyncInMemoryStorage()
    st_async = AsyncInMemoryStorage()

    with pytest.raises(NotInitializedException):
        sm_sync = SessionManager.create(st_sync,  DeletingOTPKPolicy)

    sm_async = SessionManager.create(st_async, DeletingOTPKPolicy)
    assert isinstance(assertPromiseRejected(sm_async), NotInitializedException)

def test_create_storedInfo():
    st_sync, _, st_async, _ = createSessionManagers()

    sm_sync  = SessionManager.create(st_sync,  DeletingOTPKPolicy)
    sm_async = SessionManager.create(st_async, DeletingOTPKPolicy)

    assert isinstance(sm_sync, SessionManager)
    assert isinstance(assertPromiseFulfilled(sm_async), SessionManager)

def test_deviceList():
    st_sync, sm_sync, st_async, sm_async = createSessionManagers()

    getDevices(sm_sync, sm_async, None,  [], [ A_DID ])
    getDevices(sm_sync, sm_async, A_JID, [], [ A_DID ])
    
    newDeviceList(sm_sync, sm_async, A_DIDS, A_JID)
    getDevices(sm_sync, sm_async, A_JID, [], A_DIDS)
    
    newDeviceList(sm_sync, sm_async, A_DIDS[:2], A_JID)
    getDevices(sm_sync, sm_async, A_JID, A_DIDS[2:], A_DIDS[:2])
    
    newDeviceList(sm_sync, sm_async, [], A_JID)
    getDevices(sm_sync, sm_async, A_JID, set(A_DIDS) - set([ A_DID ]), [ A_DID ])

def test_todo():
    assert False
