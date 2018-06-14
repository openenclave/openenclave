[Index](index.md)

---
# oe_spin_init()

Initializes a spin lock.

## Syntax

    oe_result_t oe_spin_init(oe_spinlock_t *spinlock)
## Description 

This function initializes a spin lock. Spin locks can also be initialized statically as follows.

```
static oe_spinlock_t _spinlock = OE_SPINLOCK_INITIALIZER;
```



Once initialized, threads may use a spin lock to synchronize access to data. See [oe_spin_lock()](thread_8h_aae5e20184eceaab7f098965c736822a9_1aae5e20184eceaab7f098965c736822a9.md) and [oe_spin_unlock()](thread_8h_a0adcf530f702c9fb7b2e4e4a2fc61ccb_1a0adcf530f702c9fb7b2e4e4a2fc61ccb.md).



## Parameters

#### spinlock

Initialize the given spin lock.

## Returns

OE_OK the operation was successful

## Returns

OE_INVALID_PARAMETER one or more parameters is invalid

---
[Index](index.md)

