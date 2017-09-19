[Index](index.md)

---
# OE_CondBroadcast()

Signals all threads waiting on a condition variable.

## Syntax

    int OE_CondBroadcast(OE_Cond *cond)
## Description 

A thread calls this function to signal all threads waiting on the given condition variable. Waiting threads call [OE_CondWait()](thread_8h_a681a086a647cf9d4af673b130e011136_1a681a086a647cf9d4af673b130e011136.md), which places them on a first-come first-served (FCFS) queue, where they wait to be signaled. [OE_CondBroadcast()](thread_8h_a089e8fbdce8abbbc6591222dec91ddb3_1a089e8fbdce8abbbc6591222dec91ddb3.md) wakes up all threads on the queue, causing them to return from [OE_CondWait()](thread_8h_a681a086a647cf9d4af673b130e011136_1a681a086a647cf9d4af673b130e011136.md). In enclaves, this function performns an OCALL, where it wakes all waiting threads.



## Parameters

#### cond

The condition variable to be signaled.

## Returns

Returns zero on success.

---
[Index](index.md)

