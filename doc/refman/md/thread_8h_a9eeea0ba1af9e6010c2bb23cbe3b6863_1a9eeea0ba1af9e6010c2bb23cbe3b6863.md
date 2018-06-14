[Index](index.md)

---
# oe_mutex_init()

Initialize a mutex.

## Syntax

    oe_result_t oe_mutex_init(oe_mutex_t *mutex)
## Description 

This function initializes a mutex. All mutexes are recursive. Once initialized, multiple threads can use this mutex to synchronize access to data. See [oe_mutex_lock()](thread_8h_a704737666b1716f0dd65dd0a02582ec1_1a704737666b1716f0dd65dd0a02582ec1.md) and [oe_mutex_unlock()](thread_8h_a2c71ea40c4b81758c620f85ff8c0d648_1a2c71ea40c4b81758c620f85ff8c0d648.md).



## Parameters

#### mutex

Initialize this mutex.

## Returns

OE_OK the operation was successful

## Returns

OE_INVALID_PARAMETER one or more parameters is invalid

---
[Index](index.md)

