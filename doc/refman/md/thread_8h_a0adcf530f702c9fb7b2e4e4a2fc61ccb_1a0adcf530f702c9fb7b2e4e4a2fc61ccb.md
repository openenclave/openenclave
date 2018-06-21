[Index](index.md)

---
# oe_spin_unlock()

Release the lock on a spin lock.

## Syntax

    oe_result_t oe_spin_unlock(oe_spinlock_t *spinlock)
## Description 

A thread calls this function to release a lock on a spin lock.



## Parameters

#### spinlock

Unlock this spin lock.

## Returns

OE_OK the operation was successful

## Returns

OE_INVALID_PARAMETER one or more parameters is invalid

---
[Index](index.md)

