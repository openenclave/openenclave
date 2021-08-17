Pthreads Implementation for SGX
===========

Many libraries (`libevent`, standard C++ threads, [MKL-DNN](https://oneapi-src.github.io/oneDNN/understanding_memory_formats.html), etc)
require basic ability to create threads and wait for the threads to complete (join).

OE currently lacks such a minimal pthreads implementation which makes it harder
to enable running verious workloads within enclaves.

This proposal aims to add a minimal pthreads implementation to OE.
It is currently targeted towards SGX since OP-TEE currently does not support
multiple enclave threads.

Prior work
- [Proposal for pthread library support in OE](https://github.com/openenclave/openenclave/pull/3697)
  This is an earlier proposal for adding pthreads functionality to OE for SGX.
  This PR seems to have been abandoned.

- OE's pthreads implementation for running libcxx tests.
  libcxx tests require minimal pthreads implementation. OE has long had a minimal pthreads
  implementation that is used by libcxx tests.
  - host side: https://github.com/openenclave/openenclave/blob/f8b952ad3bea94fe8d799bcbf614c0600c9b9e3c/tests/libcxx/host/host.cpp#L55-L219
  - enclave side: https://github.com/openenclave/openenclave/blob/f8b952ad3bea94fe8d799bcbf614c0600c9b9e3c/tests/libcxx/enc/enc.cpp#L59-L257

- Pthreads implementation used by oeapkman samples.
  oeapkman enables using a large number of libraries within enclaves.
  Lots of the libraries demonstrated via samples and testcases, require pthread support.
  Therefore, oeapkman samples have a pthreads implementation that is complete enough to
  get various libraries working
  - enclave side: https://github.com/anakrish/openenclave/blob/ak-tools-apkman/tests/tools/apkman/utils/pthread_enc.c
  - host side: https://github.com/anakrish/openenclave/blob/ak-tools-apkman/tests/tools/apkman/utils/pthread_host.c

- MUSL's pthreads implementation
  MUSL has a complete pthreads implementation. However, this PR threads
  implementation requires many syscalls that OE currently does not support.
  Depending upon how OE SDK evolves, one approach would be to implement the
  missing syscalls and then use MUSl's pthreads implementation. However,
  currently this is a significant undertaking. It is also not clear whether
  there is need for all pthreads functionably within enclaves.


Supported API


The following pthread API will be supported:

- [pthread_attr_init](https://man7.org/linux/man-pages/man3/pthread_attr_init.3.html)
  ```c
  int pthread_attr_init(pthread_attr_t *attr);
  ```
  This function is used to initialize an instance of `pthread_attr_t` structure that is passed
  to `pthread_create`.
  The implementation of this function sets all the fields of the structure to zero.


- [pthread_attr_destroy](https://man7.org/linux/man-pages/man3/pthread_attr_init.3.html)
  ```c
  int pthread_attr_destroy(pthread_attr_t *attr);
  ```
  This function is used to clean up an instance of `pthread_attr_t`.
  The implementation of this function sets all the fields of the structure to zero.

- [pthread_attr_setdetachstate](https://man7.org/linux/man-pages/man3/pthread_attr_setdetachstate.3.html)
  ```c
  int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate);
  ```
  Currently `detachstate` is the only supported thread attribute.

  Other `pthread_attr_*` functions are not available and would result in link error if used
  within an enclave.

  By default `detachstate` is `PTHREAD_CREATE_JOINABLE` which means that the thread is joinable.
  If a thread is `joinable`, then another thread can wait for it to complete via `pthread_join`.

  A thread can be created as `detached` by setting the `detachstate` to `PTHREAD_CREATE_DETACHED`.
  A detached thread cannot be joined. It's resourses are released as soon as the thread is terminated.


- [pthread_create](https://man7.org/linux/man-pages/man3/pthread_create.3.html)

  ```c
  int pthread_create(pthread_t *restrict thread,
                     const pthread_attr_t *restrict attr,
                     void *(*start_routine)(void *),
                     void *restrict arg);
  ```

  Create a new thread using the specified attributes.
  If successful, `0` is returned. Otherwise an error (typically `EAGAIN`) is returned.

  The `start_routine` is pointer to a function that will be called by the newly created thread.
  The `arg` parameter is supplied to the `start_routine` which can return a `void *` value.

  The `thread` parameter will be set to the id of the newly created thread.


- [pthread_exit](https://man7.org/linux/man-pages/man3/pthread_exit.3.html)
  ```c
  noreturn void pthread_exit(void *retval);
  ```

  This

- [pthread_detach]()
  ```c
  ```

- [pthread_join]()
  ```c
  ```

The design is based on oeapkman's utility pthreads library. A detailed reading would also reveal
that it is similar to the earlier proposal above.

  Design implication:
  - Joinable threads
    - The return value of the thread must be kept around after the thread termination, till another
	  thread joins it.
	- The thread id of a joinable thread can be reused only after
  - Detached threads
    - The return value can be discarded immediately after the thread terminates.
	- The thread id can be reused immediately after the thread terminates.

  The house-keeping data associated with a thread in maintained in a structure `oe_thread_info_t`.
  ```c
  typedef struct _thread_info
{
    // The id of this thread. Monotonically increasing calue that
    // is unique within the enclave.
    oe_pthread_t pthread_id;
    // The id of the corresponding host thread.
    uint64_t host_thread_id;

    // Thread function and argument.
    void* (*function)(void*);
    void* arg;

    // The return value of the thread function.
    // This can also be set via pthread_exit.
    void* ret_val;

    // The jmp_buf used by pthread_exit.
    oe_jmp_buf jmp_buf;

    // Is this thread joinable.
    bool joinable;
    bool joined;
    bool terminated;

    // Linked list nodes.
    struct _thread_info* next;
    struct _thread_info* prev;

    uint64_t ref_count;

} oe_thread_info_t;
  ```
