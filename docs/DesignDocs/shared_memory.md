The Open Enclave shared memory model
====================================

This document proposes a *shared memory model* that will improve
interoperability across different secure hardware platforms, initially
including SGX and TrustZone.

Motivation
----------

Ideally, applications developed with the Open Enclave API should run on all
supported platforms. But unfortunately, the platforms themselves may have
incompatible shared memory models. For example, SGX implicity shares all
untrusted memory with the enclave, whereas TrustZone shares untrusted memory
explicitly through programmatic measures.

This problem is partly addressed by the PR entitled [Enforcing full
serialization in EDL](https://github.com/openenclave/openenclave/pull/2176),
which proposes **edger8r** options that reject EDL specifications that cannot
be fully serialized. Such specifications produce applications that implicitly
share untrusted memory with the enclave. Aside from introducing potential
security flaws, these applications are not portable to TrustZone and any future
platforms that employ a similar model. By forcing full serialization, the need
for shared memory can be mostly eliminated. But sometimes applications need to
pass untrusted shared memory to enclaves. A few of examples include:

- Ring buffers
- Context-switchless calls
- Efficient transfer of large memory objects

Whatever the reasons, a mechanism is needed for sharing untrusted memory with
the enclave and that mechanism must be interoperable across secure hardware
platforms. Further, the mechanism must be explicit and operations are needed
for managing untrusted memory.

User Experience
---------------

The host may share untrusted memory with the enclave through the use of the
**user_check** EDL attribute. For example:

```c++
enclave
{
    trusted
    {
        void share_buffer_ecall(
            [user_check] void* untrusted_memory,
            size_t untrusted_memory_size);
    };
};
```

We assume in this example that the enclave needs to read or write the
**untrusted_memory** buffer. Prior to this proposal, SGX applications
could pass any pointer to untrusted memory. For example:

```c++
    static unsigned char buf[4096];

    share_buffer_ecall(buf, sizeof(buf));
```

But this application is not portable to TrustZone since **buf** is not visible
within the enclave. To make this work on TrustZone, the buffer should be
explicitly allocated from a shared memory pool as follows.

```c++
    const size_t n = 4096;
    unsigned char* buf;

    if (oe_allocate_shared_memory(enclave, n, &buf) != OE_RESULT_OK)
    {
        /* Error */
    }

    memset(buf, 0, n);

    share_buffer_ecall(buf, n);
```

This program fragment will work on both SGX and TrustZone. The application
will eventually free this buffer by passing it to **oe_free_shared_memory()**.

The enclave's implementation of **share_buffer_ecall()** should verify that
the **untrusted_memory** is fully contained within shared memory as shown
below.

```c++
void share_buffer_ecall(void* untrusted_memory, size_t untrusted_memory_size)
{
    if (!oe_is_shared_memory(untrusted_memory, untrusted_memory_size)
    {
        /* Error! */
    }
    ...
}
```

Specification
-------------

This design introduces the following functions on the host side:

```c++
    oe_result_t oe_allocate_shared_memory(
        oe_enclave_t* enclave,
        size_t size,
        void** ptr);

    oe_result_t oe_free_shared_memory(
        oe_enclave_t* enclave,
        void* ptr);

    bool oe_is_shared_memory(
        oe_enclave_t* enclave,
        const void* ptr,
        size_t size);

    typedef enum _oe_memory_type
    {
        /* !oe_is_trusted_memory() && !oe_is_shared_memory() */
        OE_MEMORY_TYPE_UNKNOWN,

        /* oe_is_trusted_memory() */
        OE_MEMORY_TYPE_TRUSTED,

        /* oe_is_shared_memory() */
        OE_MEMORY_TYPE_SHARED,
    }
    oe_memory_type_t;

    oe_result_t oe_get_memory_type(
        oe_enclave_t* enclave,
        const void* ptr,
        size_t size,
        oe_memory_type_t* type);
```

The same functions are available on the enclave side but without the enclave
parameter.

```c++
    oe_result_t oe_allocate_shared_memory(
        size_t size,
        void** ptr);

    oe_result_t oe_free_shared_memory(
        void* ptr);

    bool oe_is_shared_memory(
        const void* ptr,
        size_t size);

    typedef enum _oe_memory_type
    {
        /* !oe_is_within_enclave() && !oe_is_shared_memory() */
        OE_MEMORY_TYPE_UNKNOWN,

        /* oe_is_within_enclave() */
        OE_MEMORY_TYPE_TRUSTED,

        /* oe_is_shared_memory() */
        OE_MEMORY_TYPE_SHARED,
    }
    oe_memory_type_t;

    oe_result_t oe_get_memory_type(
        const void* ptr,
        size_t size,
        oe_memory_type_t* type);
```

Assumptions:

- All shared memory is read-write (non-executable). No mechanism is provided
  for allocating read-only memory ore executable memory.

- Shared TrustZone memory is visible at the same address on both the host and
  the enclave (hence all shared memory is zero-copy).

Alternatives
------------

No other alternatives have been considered.

Authors
-------

Mike Brasher - mikbras@microsoft.com
