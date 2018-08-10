[Index](index.md)

---
# oe_rwlock_unlock()

Release a read lock on a readers-writer lock.

## Syntax

    oe_result_t oe_rwlock_unlock(oe_rwlock_t *rwLock)
## Description 

This function releases the lock on a readers-writer lock obtained with one of these:

-  [oe_rwlock_rdlock()](thread_8h_a3cbefb95278426a3c424bd84782e7f8f_1a3cbefb95278426a3c424bd84782e7f8f.md)

-  [oe_rwlock_try_rdlock()](thread_8h_a72ebfc6c036b0366cdf05b180569f80f_1a72ebfc6c036b0366cdf05b180569f80f.md)

-  [oe_rwlock_try_wrlock()](thread_8h_a58ef319c60aade7affcf2048a268e6cd_1a58ef319c60aade7affcf2048a268e6cd.md)

- or [oe_rwlock_try_wrlock()](thread_8h_a58ef319c60aade7affcf2048a268e6cd_1a58ef319c60aade7affcf2048a268e6cd.md)

Behavior:

Undefined behavior:



## Parameters

#### rwLock

Release the lock on this readers-writer lock.

## Returns

OE_OK the operation was successful.

## Returns

OE_INVALID_PARAMETER one or more parameters is invalid.

## Returns

OE_NOT_OWNER the calling thread does not have this object locked.

## Returns

OE_NOT_BUSY readers still exist.

---
[Index](index.md)

