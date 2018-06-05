[Index](index.md)

---
# OE_RWLockDestroy()

Destroys a readers-writer lock and for use inside an enclave.

## Syntax

    int OE_RWLockDestroy(OE_RWLock *rwLock)
## Description 

This function destroys a readers-writer lock and releases any resources used by the lock. The lock must be in an unlocked state.

Undefined behavior:



## Parameters

#### Destroy

this readers-writer lock.

## Returns

Returns zero on success.

---
[Index](index.md)

