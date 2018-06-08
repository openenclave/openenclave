[Index](index.md)

---
# oe_rwlock_destroy()

Destroys a readers-writer lock.

## Syntax

    int oe_rwlock_destroy(oe_rwlock_t *rwLock)
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

