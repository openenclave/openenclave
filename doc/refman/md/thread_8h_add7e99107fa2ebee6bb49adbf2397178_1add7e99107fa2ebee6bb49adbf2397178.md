[Index](index.md)

---
# OE_RWLockInit()

Initializes a readers-writer lock.

## Syntax

    int OE_RWLockInit(OE_RWLock *rwLock)
## Description 

OE_RWLockInit initializes the lock to an unlocked state. Readers-writer locks can also be initialized statically as follows.

```
OE_RWLock rwLock = OE_RWLOCK_INITIALIZER;
```



Undefined behavior:



## Parameters

#### rwLock

Initialize this readers-writer variable.

## Returns

Returns zero on success.

---
[Index](index.md)

