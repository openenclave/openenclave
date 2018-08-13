[Index](index.md)

---
# oe_rwlock_unlock()

Release a read lock on a readers-writer lock.

## Syntax

    oe_result_t oe_rwlock_unlock(oe_rwlock_t *rwLock)
## Description 

This function releases the lock on a readers-writer lock obtained with one of these:

-  [oe_rwlock_rdlock()](thread_8h_a3cbefb95278426a3c424bd84782e7f8f_1a3cbefb95278426a3c424bd84782e7f8f.md)

-  [oe_rwlock_tryrdlock()](thread_8h_a92b5c9cca43cd1a83eb095b78813e26c_1a92b5c9cca43cd1a83eb095b78813e26c.md)

-  [oe_rwlock_trywrlock()](thread_8h_a9dd482e6d9447f2bbcf911a09726c85e_1a9dd482e6d9447f2bbcf911a09726c85e.md)

- or [oe_rwlock_trywrlock()](thread_8h_a9dd482e6d9447f2bbcf911a09726c85e_1a9dd482e6d9447f2bbcf911a09726c85e.md)

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

