[Index](index.md)

---
# OE_CondBroadcast()

Signals all threads waiting on a condition variable.

## Syntax

    int OE_CondBroadcast(
        cond);
## Description 

A thread calls this function to signal all threads waiting on the given condition variable. Waiting threads call OE_CondWait(), which places them on a first-come first-served (FCFS) queue, where they wait to be signaled. OE_CondBroadcast() wakes up all threads on the queue, causing them to return from OE_CondWait(). In enclaves, this function performns an OCALL, where it wakes all waiting threads.



## Parameters

#### cond

The condition variable to be signaled.

## Returns

Returns zero on success.

---
[Index](index.md)

