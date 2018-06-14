[Index](index.md)

---
# oe_rwlock_destroy()

Destroys a readers-writer lock.

## Syntax

    oe_result_t oe_rwlock_destroy(oe_rwlock_t *rwLock)
## Description 

This function destroys a readers-writer lock and releases any resources used by the lock. The lock must be in an unlocked state.

Undefined behavior:



## Parameters

#### Destroy

this readers-writer lock.

## Returns

OE_OK the operation was successful

## Returns

OE_INVALID_PARAMETER one or more parameters is invalid

## Returns

OE_BUSY threads are still waiting on this lock

---
[Index](index.md)

