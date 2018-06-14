[Index](index.md)

---
# oe_rwlock_try_wrlock()

Tries to acquire a write lock on a readers-writer lock.

## Syntax

    oe_result_t oe_rwlock_try_wrlock(oe_rwlock_t *rwLock)
## Description 

Behavior:

Undefined behavior:



## Parameters

#### rwLock

Acquire a write lock on this readers-writer lock.

## Returns

OE_OK the operation was successful

## Returns

OE_INVALID_PARAMETER one or more parameters is invalid

## Returns

OE_BUSY the lock was busy

---
[Index](index.md)

