Pluggable Allocators
=====

Open Enclave provides a default memory allocator for enclaves.
This default allocator, [dlmalloc (Doug Lea Malloc)](http://gee.cs.oswego.edu/dl/html/malloc.html), is public domain, popular, and also serves as the basis for glibc's allocator. It is also easily modified to work within enclaves. However, it not performant in multi-threaded applications.

There are various high-performance memory allocators that try to optimize, among other things, multi-threaded scenarios:
- [The GNU Allocator](https://www.gnu.org/software/libc/manual/html_node/The-GNU-Allocator.html) which is based on `pthreads malloc`, which is in turn based on `dlmalloc`.
- [Thread-Caching Malloc (tcmalloc)](https://gperftools.github.io/gperftools/tcmalloc.html).
- [snmalloc](https://github.com/Microsoft/snmalloc).
- Many others, such as application-specific allocators that often outperform general-purpose allocators.


This document describes the design of a scheme to allow custom allocators to be used in enclaves.


Precedents
------

- The GNU C Library provides a way to replace its malloc implementation, documented in [Replacing Malloc](https://www.gnu.org/software/libc/manual/html_node/Replacing-malloc.html#Replacing-malloc). </br>
  To replace the allocator, the following replacement functions must be provided `malloc`, `free`, `calloc`, `realloc`, `aligned_alloc`, `malloc_usable_size`, `memalign`, `posix_memalign`, `palloc`, and `valloc`. </br>
  Replacement happens by statically linking the allocator library before the GNU C Library.

- This document covers compiling the Open Enclave SDK to use `snmalloc` (Pull Request #2649). Currently, users must recompile OE SDK with `USE_SNMALLOC` to leverage this.

- Rust Language is [considering](https://doc.rust-lang.org/1.15.1/book/custom-allocators.html) capability to switch out the default allocators (`alloc_system` and `alloc_jemalloc`).


Non-Requirements
-----

- This design does not aim to address what the ideal default allocator for Open Enclave should be.
- Though the design could be extended to support multiple pluggable allocators, each managing a portion of the heap, it is currently a non-requirement.

Requirements
----

The design for `Pluggable Allocators` additionally has the following requirements,

- Allocators must be pluggable by an SDK user without having to recompile the OE SDK </br>
  This is similar to the GNU C library in that one need not rebuild glibc to plug in a malloc replacement.

- Must work on various TEE environments that the Open Enclave SDK will support. </br>
  Note, it does not mean that a given allocator must work on all platforms; rather Open Enclave SDK must support plugging allocators on all platforms. </br>
  From a design perspective, this precludes the use of architecture specific data structures in the plugin interface.

- The design must support building existing functionality like `failure callbacks` and `debug allocators` atop custom allocators.

- The design must allow allocators to perform thread-specific optimizations since multi-threaded applications benefit a lot from fine-tuned allocators.

- Allocators must rely only on published interfaces and datastructures.

- The design must allow for Open Enclave core (`liboecore`) to own a portion of the heap and have the allocator manage rest of the heap. </br>
  This allows the SDK to manage a bit of memory for efficiently dispatching ecalls/ocalls, logging, and other core features, better than what a general-purpose
  allocator would be capable of. Additionally, it also allows a clear memory demarcation between `core memory` and `application memory`.

- Performance and safety. Plugin approaches often involve registering `hook` functions that will be called by the SDK via indirect calls.
  It is desirable to avoid indirect calls since they are not performant. Additionally, indirect calls are subject to speculative execution side-channels.

- Backwards-compatibility. No existing clients must require any change to get the default allocator.


Design
---

A custom allocator must provide a set of replacement functions. They are declared in the published header `openenclave/advanced/allocator.h`. The set of replacement functions are mostly equivalents of the functions required by the GNU C Library for plugging-in custom allocators. Additionally, there are replacement functions that allow the allocator to work well with enclave threads.
The SDK will provide default implementations of these functions that will result in the use of the default allocator.

If no replacement functions are provided, then the default allocator is used. This retains the current behavior in which all enclaves get the default allocator without any additional linker options. Providing a partial set of replacement functions would result in linker error.

The replacement functions can be provided
- via object files. This happens when the allocator is not a separate static library.
- via a separate allocator static library. In this case, the allocator library must be specified before `oelibc` in the linker command line. </br>


Note,  ELF  `weak symbols` (see [Function Attributes](https://gcc.gnu.org/onlinedocs/gcc-3.2/gcc/Function-Attributes.html)) are designed to allow user code to override functions defined in libraries. Using `weak symbols` for default implementation of these function would cause the linker to look for custom replacement functions irrespective of the order. However, if only a partial set of replacement functions are provided, then weak symbols would result in the linker picking the default implementations for the rest of the functions. To avoid a mix of API from different allocators, the default implementations shall not be weak symbols.


Replacement functions are not required to be reentrant.

Undefined Behavior
---

- The replacement functions should not do much other than managing memory. Making ocalls, logging, printf etc may use dynamic memory and hence result in reentranct calls to the allocator.
- All the replacement functions must be provided, or none. A partial set will result in both the default allocator and the custom allocator managing the heap.


Replacement Functions
---

Published in `openenclave/advanced/allocator.h`

- `void oe_allocator_init(void* heap_start_address, void* heap_end_address)` </br>
  This function will be called by `oecore` at an appropriate time during enclave initialization. The total heap memory available to the enclave is specified in its configuration file or in a macro such as OE_SET_ENCLAVE_SGX or OE_SET_ENCLAVE_OPTEE
  (e.g [hello_world.conf](https://github.com/openenclave/openenclave/blob/e2e440ec134d37e107b5a296fdc508a3a643598e/samples/helloworld/enclave/helloworld.conf#L6)) </br>
  `oecore` may reserve a small portion for its own use and pass the rest to this replacement function. The allocator is expected to perform any global initialization in this function. </br>
  This function is called prior to any global initialization.


- `void oe_allocator_cleanup(void)` </br>
  This function will be called by `oecore` at an appropriate time during enclave termination. `atexit` functions will be executed prior to `oe_allocator_cleanup`. </br>
  `oe_allocator_cleanup` may not register functions with `atexit`.


- `void oe_allocator_thread_init(void)` </br>
  This function will be called by `oecore` during initialization of an enclave thread, after the thread-local variables for the thread have been initialized. </br>
  In the future, if `oecore` needs to hold onto any thread-specific data on behalf of the allocator, it can be returned in this function. Currently the recommendation is to use `__thread` variables to store thread-specific allocator data.


- `void oe_allocator_thread_cleanup(void)` </br>
  This function will be called by `oecore` just prior to the termination of enclave thread.
  Thread-specific exit functions (`__cxa_thread_atexit` functions) will be executed prior to `oe_allocator_thread_cleanup`. </br>
  This allows the thread-specific exit functions to use memory management functions (e.g to free resources) before the allocator itself is cleaned up. </br>
  It is recommended that allocators be judicious about using C++11 thread-specific objects in `oe_allocator_thread_cleanup` since
  use of C++11 thread-local objects may trigger a call to (`__cxa_thread_atexit`) after all the thread-specific exit functions have executed.


  It is important that the allocators be aware of the nature of enclave threads, and be designed accordingly. Enclave threads can be short-lived. For OE SGX, enclave threads last only for the duration of an ecall. </br>
  Additionally, the same thread-control structure (e.g., `sgx_tcs_t` for SGX) can be bound to different host threads at different times during the lifespan of an enclave.


- `void* oe_allocator_malloc(size_t size)` </br>
  This function will be called by `oecore` to implement `malloc`. Depending upon the build settings, the allocated memory might be tracked by the `debug-malloc` feature. `oe_allocator_malloc` must provide the same semantics as [malloc](https://en.cppreference.com/w/c/memory/malloc).


- `void oe_allocator_free(void* ptr)` </br>
  This function will be called by `oecore` to implement `free`. `oe_allocator_free` must provide the same semantics as [free](https://en.cppreference.com/w/c/memory/free).


- `void* oe_allocator_calloc(size_t nmemb, size_t size)` </br>
  This function will be called by `oecore` to implement `calloc`. `oe_allocator_calloc` must provide the same semantics as [calloc](https://en.cppreference.com/w/c/memory/calloc).


- `void* oe_allocator_realloc(void* ptr, size_t size)` </br>
  This function will be called by `oecore` to implement `realloc`. `oe_allocator_realloc` must provide the same semantics as [realloc](https://en.cppreference.com/w/c/memory/realloc).

- `void* oe_allocator_aligned_alloc(size_t alignment, size_t size)` </br>
  This function will be called by `oecore` to implement [aligned_alloc](https://linux.die.net/man/3/aligned_alloc/man/3/posix_memalign). Memory allocated by this function can be freed via `free`.

- `void oe_allocator_posix_memalign(void** memptr, size_t alignment, size_t size)` </br>
  This function will be called by `oecore` to implement [posix_memalign](https://linux.die.net/man/3/posix_memalign). Memory allocated by this function can be freed via `free`.

- `size_t oe_allocator_malloc_usable_size(void* ptr)` </br>
  This function is called by `oecore` to implement [malloc_usable_size](http://man7.org/linux/man-pages/man3/malloc_usable_size.3.html). </br>
  This function must be implemented.



In comparison to GNU C Library, `oecore` does not require the allocator to implement `memalign`, `palloc` and `valloc`. These functions are obsolete and are will not be available.
