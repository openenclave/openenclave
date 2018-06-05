[Index](index.md)

---
# OE_SpinUnlock()

Release the lock on a spin lock and for use inside an enclave.

## Syntax

    int OE_SpinUnlock(OE_Spinlock *spinlock)
## Description 

A thread calls this function to release a lock on a spin lock.



## Parameters

#### spinlock

Unlock this spin lock.

## Returns

Return zero if successful

---
[Index](index.md)

