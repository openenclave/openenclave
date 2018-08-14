[Index](index.md)

---
# oe_mutex_trylock()

Try to acquire a lock on a mutex.

## Syntax

    oe_result_t oe_mutex_trylock(oe_mutex_t *mutex)
## Description 

This function attempts to acquire a lock on the given mutex if it is available. If the mutex is unavailable, the function returns immediately. Unlike [oe_mutex_lock()](thread_8h_a704737666b1716f0dd65dd0a02582ec1_1a704737666b1716f0dd65dd0a02582ec1.md), this function never performs an OCALL.



## Parameters

#### mutex

Acquire a lock on this mutex.

## Returns

OE_OK the operation was successful

## Returns

OE_INVALID_PARAMETER one or more parameters is invalid

## Returns

OE_BUSY the lock was busy

---
[Index](index.md)

