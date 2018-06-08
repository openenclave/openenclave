[Index](index.md)

---
# oe_mutex_unlock()

Releases a mutex.

## Syntax

    int oe_mutex_unlock(oe_mutex_t *mutex)
## Description 

This function releases the lock on a mutex obtained with either [oe_mutex_lock()](thread_8h_a7d64c3e4796b8e037565f3828eebd678_1a7d64c3e4796b8e037565f3828eebd678.md) or [oe_mutex_try_lock()](thread_8h_ac1af93501419169a3119ce6e6680ec35_1ac1af93501419169a3119ce6e6680ec35.md).

In enclaves, this function performs an OCALL, where it wakes the next thread waiting on a mutex.



## Parameters

#### mutex

Release the lock on this mutex.

## Returns

Returns zero on success.

---
[Index](index.md)

