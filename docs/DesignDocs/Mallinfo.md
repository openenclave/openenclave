Malloc Info
===========

Some Open Enclave tests need access to either available heap space, or the allocated heap space so far:

- [bigmalloc](https://github.com/openenclave/openenclave/blob/master/tests/bigmalloc) uses that information to check it can allocate 99% of remaining memory successfully.
- [memory](https://github.com/openenclave/openenclave/blob/master/tests/memory) tries to allocate fixed and random sized chunks that fit in remaining memory.

They currently either rely on the allocator providing `sbrk()`, or `dlmallinfo()` to obtain this information.

The [Pluggable Allocator Interface](https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/PluggableAllocators.md) doesn't expose either of those calls however, and so it isn't possible to run these tests when using allocators other than dlmalloc as a result. This document proposes introducing an `oe_allocator_mallinfo()` as an optional extension to the Pluggable Allocator Interface to address this problem.

Once this interface is defined, it can be implemented for the allocators that ship with Open Enclave, and the tests can be modified to make use of it.

Depending on the exact TEE in use, enclave memory usage may be capped to a hard limit set at startup, and difficult or impossible to obtain with normal operating system tools. Operators executing applications in enclave on these platforms may want access to information about memory usage to monitor and plan capacity accordingly.

If a standard memory usage API is provided via `oe_allocator_mallinfo()`, application writers can expose memory usage information to operators across TEEs and allocator implementations to facilitate monitoring and capacity planning.

Precedents
------

- dlmalloc provides a [`dlmallinfo()`](https://github.com/openenclave/openenclave/blob/master/3rdparty/dlmalloc/dlmalloc/malloc.h#L307) call exposing various internal metrics.
- tcmalloc has a mechanism to extract and print internal [stats](https://github.com/google/tcmalloc/blob/002b4f00d96701cfd43db3546cdeb63eb35d244e/tcmalloc/page_allocator.h#L56), the older gperftools variant included in the Intel SGX SDK exposes [tc_mallinfo](https://github.com/intel/linux-sgx/blob/c505e6129a8c95852045e5ec8b08b1b230a8952a/sdk/gperftools/gperftools-2.7/src/tcmalloc.cc#L1627)
- mimalloc tracks extensive internal [stats](https://github.com/microsoft/mimalloc/blob/master/doc/mimalloc-doc.h#L307) and can print them out.
- snmalloc tracks extensive internal [stats](https://github.com/microsoft/snmalloc/blob/d900e294243ede0c1f4ccd2f04a8dd6fab78e1ed/src/mem/allocstats.h), but only when USE_SNMALLOC_STATS is enabled. @mjp41 is looking at enabling a small subset of these values more permanently and with a lower performance cost.

Non-Requirements
-----

- This design does not aim to abstract across detailed, allocator-specific information.

Requirements
----

The design must allow all existing test cases to be modified in such a way that they cover the same functionality but no longer need to use allocator-specific calls and can instead rely on `oe_allocator_mallinfo()`.

The design also aims to make it possible for operators to run an Open Enclave-based service with the same ease as a non-Open Enclave one, with respect to monitoring memory usage and planning initial process allocation accordingly. This is typically done with operating system-level tools which are agnostic to both hardware and specific allocator implementations.

Design
---

Allocators can implement an `oe_allocator_mallinfo()` call:

```
struct oe_mallinfo_t {
  size_t max_total_heap_size;
  size_t current_allocated_heap_size;
  size_t peak_allocated_heap_size;
}

oe_result_t oe_allocator_mallinfo(struct oe_mallinfo_t * info);
```

The allocator will set `max_total_heap_size` to the maximum number of bytes it can allocate in total, and `current_allocated_heap_size` to the number of bytes allocated at the moment. `peak_allocated_heap_size` will contain the highest value reached by `current_allocated_heap_size` during execution.

Successful calls return OE_OK. The allocator may return OE_UNSUPPORTED if it does not support the interface, or OE_FAILURE for other failures.
