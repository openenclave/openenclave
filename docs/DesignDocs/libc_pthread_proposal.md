# To support pthread in Open Enclave SDK

Currently, pthread management APIs are not implemented in OE SDK while they are
implemented in SGX SDK. The pthread APIs are added when porting MKL-DNN to SGX SDK.
To get better performance, MKL-DNN should be configured to build with OpenMP which
depends on pthread.

## New APIs

### oe_thread_create
The function is used to create a new thread inside enclave.

oe_thread_create is an internal function which will be wrapped to an external API pthread_create.

The work sequence should be like,
* Parent thread(Enclave): call pthread_create() inside the enclave codes written by users.
* Parent thread(Enclave): initialize some structures and execute OCALL - OE_OCALL_THREAD_CREATE.
* Parent thread(Host): allocate some resources and call oe_thread_create() to create a new thread.
* Child thread(Host): execute ECALL - OE_ECALL_THREAD_CREATE_ROUTINE if new thread is created successfully.
* Child thread(Enclave): get the user defined hook function and execute it.

**NOTE**: Currently the parameter of attributes for the created thread is unused. So the created threads are
all joinable.

### oe_thread_exit
The function is used to exit the start_routine function.

oe_thread_exit is an internal function which will be wrapped to an external API pthread_exit.

The work sequence should be like,
* Parent thread(Enclave): call pthread_create() to create a new thread and then return.
* Child thread(Host): execute ECALL - OE_ECALL_THREAD_CREATE_ROUTINE.
* Child thread(Enclave): call oe_setjmp() to store current execution context.
* Child thread(Enclave): execute the user defined hook function.
* Child thread(Enclave): call pthread_exit() inside user defined hook function.
* Child thread(Enclave): in pthread_exit() call oe_longjmp() to restore the context.

### oe_thread_join
This function is used to wait for the specified thread to terminate.

oe_thread_join is an internal function which will be wrapped to an external API pthread_join.

The work sequence should be like,
* Parent thread(Enclave): call pthread_create() to create a new thread and then return.
* Other threads(Enclave/Host): call pthread_join() and then make an OCALL - OE_OCALL_THREAD_WAIT to wait for an event.
* Child thread(Host): execute ECALL - OE_ECALL_THREAD_CREATE_ROUTINE.
* Child thread(Host): wake up the waiting thread after OE_ECALL_THREAD_CREATE_ROUTINE return.
* Other threads(Host): OE_OCALL_THREAD_WAIT return after being waked up.
* Other threads(Enclave): in pthread_join() check the child thread status which is controlled in enclave before return.

### oe_thread_self
The function is used to get the calling thread’s ID. 

oe_thread_self is an internal function which will be wrapped to an external API pthread_self.

Currently it returns the td pointer. It will be changed to return an internal structure pointer which 
is used in oe_thread_exit and oe_thread_join.

```
typedef struct _oe_thread_impl
{
    volatile oe_spinlock_t lock;
    volatile oe_thread_state_t state;
    oe_sgx_td_t* joiner_td;
    oe_sgx_td_t* creater_td;
    struct _oe_thread_common_queue_elm_t common_queue_elm;
    void* (*start_routine)(void *);
    void* arg;
    void* retval;  // Used by oe_thread_exit() and oe_thread_join() to pass the exit message
    void* tid;
} oe_thread_impl_t
```

## Support OSes
To get better performance, the OS thread created in host should be detached. Currently the OS thread can be created 
by oe_thread_create which is a wrapper of pthread_create in Linux and CreateThread in Windows. The attribute parameter 
is not used, so the detached thread can't be created with default attribute. However, if only Linux is supported, there will be 
no issue.

Refer to - https://github.com/openenclave/openenclave/issues/3597
