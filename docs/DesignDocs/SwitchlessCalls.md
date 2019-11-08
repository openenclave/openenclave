Context-switchless Calls
================

## Motivation

Context-switchless Calls are designed to reduce the cost of context switching between hosts and enclaves.
In an enclave application, the host makes **ECALL**s into functions exposed by the enclaves it created. Likewise,
the enclaves may make **OCALL**s into functions exposed by the host that created them. In either case, the
execution has to be transitioned from an untrusted environment to a trusted environment, or vice versa. Since the
transition is costly due to heavy security checks, for example, instruction `EENTER` alone could take hundreds of CPU
cycles, it might be more performance advantageous to make the calls
**context-switchless**: the caller delegates the function call to a worker thread in the other environment, which
does the real job of calling the function and posting the result to the caller. Both the calling thread and the
worker thread never leave their respective execution contexts during the perceived function call. By having two threads
working on two different security contexts, each conforming to the security constraints of its own context, we could
achieve better function call performance without sacrificing security.

## Possible Usages

In general, the good candidates for switchless calls are functions that are:
1) short, thus the transition takes relatively a high percentage of the overall execution time of the call; and
2) called frequently, so the savings in transition time adds up.

If your enclave application has such functions and you are concerned with performance, consider making those
functions context-switchless.

## User Experience

Firstly, the user has to identify which functions are good candidates of switchless calls. The identified ones
need to be marked in the EDL file with a keyword `transition_using_threads`. For example, to mark function
`host_increment_switchless` a target of switchless calls, it has to be declared as:

```c
void host_increment_switchless([in, out] int* m) transition_using_threads;
```

Secondly, while creating an enclave, the user has to explicitly configure it to enable switchless capability.
An important setting in the configuration is how many worker threads are to be created for servicing the
context-switchless calls. More worker threads typically means more competition for the CPU cores and more thread
context switches, hurting the performance. On the other hand, fewer worker threads means simultaneously issued
switchless calls are less likely to be serviced quickly, if they got serviced at all.
We will give a guideline for users to search for the "sweet spot" of this setting.

The users are encouraged to measure the performance delta between enclave applications with
or without switchless calls, and decide on whether switchless calling should be turned on for some functions,
and/or the ideal number of worker threads.

## Specification

**Information exchanges between threads**

The calling thread and the worker thread need to exchange information twice during the call. When the switchless
call is initiated, the caller needs to pass the `job` (encapsulating information regarding the function call in a
 single object, for details see the next section) to the worker thread. And when the call finishes, the worker
thread needs to pass the result back to the caller.

**The function call as a `job`**

We use the same marshalling code for both switchless calls and regular calls. Essentially, the `job` contains
information like the function table, the function ID, the input parameters flattened in a contiguous buffer,
and reserved spaces for output parameters and return value. Since the call is represented the same way for
both switchless calls and regular calls, we have the flexibility of converting a switchless call into a
regular call, or vice versa, at any point prior to the call is fulfilled.

**Thread synchronizations**

Both exchanges between the calling thread and the worker thread need to be synchronized. Whenever possible,
we use atomic operations to such exchanges for performance reasons. We will also ensure the compiler doesn't
introduce out-of-order execution in the case one thread writes data which is then consumed by another thread. Obviously,
there is a M:N mapping between the calling threads and the worker threads. To simplify synchronization, instead
of having a queue that is shared by worker threads, we choose to set up a queue for each worker thread, so that
`jobs` posted to one worker thread do not interfere with `jobs` posted to another worker
thread. With a further simplification, we limit the queue length to 1. Effectively, this means there is at
most one `job` waiting to be serviced by a worker thread. This avoids interference between `jobs` posted to
the same worker thread, i.e., a time-consuming switchless call stalls the next switchless call on the same thread.

**Sleep/wake of worker threads**

The worker threads are idle when there are no incoming switchless calls. To save CPU cycles, we will put a
worker thread to sleep when it is idle for a prolonged period of time. Subsequently, a calling thread has to
wake it up before posting a `job` to it.

**Fallback to regular calls**

Since we have a limited number of worker threads, and the queue for each worker thread is just one, obviously
a switchless call could be dropped due to all worker threads are busy. In this case, we fall back to the regular
**ECALL**/**OCALL**.

**Security considerations**

Switchless calls depend on switchless manager, an object manages the worker threads and their queues. Since it
exists in the untrusted memory, we have to assume it could be maliciously manipulated. The switchless handling
inside the enclave must be guarded against such manipulations. In any case, deny-of-service is outside the scope
since DoS is possible even with regular ECALL/OCALLs.


**Switchless OCALLs first**

Based on customer feedback, we have decided to deliver switchless OCALLs first. Please contact us if you have
strong demand for switchless ECALLs.


Authors
-------

Xuejun Yang (xuejya@microsoft.com)

Anand Krishnamoorthi (anakrish@microsoft.com)
