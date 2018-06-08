[Index](index.md)

---
# oe_rwlock_init()

Initializes a readers-writer lock.

## Syntax

    int oe_rwlock_init(oe_rwlock_t *rwLock)
## Description 

oe_rwlock_init initializes the lock to an unlocked state. Readers-writer locks can also be initialized statically as follows.

```
oe_rwlock_t rwLock = OE_RWLOCK_INITIALIZER;
```



Undefined behavior:



## Parameters

#### rwLock

Initialize this readers-writer variable.

## Returns

Returns zero on success.

---
[Index](index.md)

