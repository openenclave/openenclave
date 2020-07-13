
# Pluggable Allocator Sample

This sample demonstrates how to replace the default memory allocator (dlmalloc) by
plugging in a custom allocator (in this case [snmalloc](https://github.com/microsoft/snmalloc))
for improved performance in multi-threaded enclaves.

# Available Allocators

OE SDK uses `dlmalloc` as the default allocator for enclaves.
`dlmalloc` has been well studied, has been around for a long time,
and has minimal space overhead.

Since `v0.10` Open Enclave SDK packages and ships `snmalloc` as a
library `oesnmalloc` that can be plugged in following the steps described below.
[snmalloc](https://github.com/microsoft/snmalloc)) is a high-performance
allocator with excellent performance [characteristics](https://github.com/microsoft/snmalloc/blob/master/snmalloc.pdf).
It has been designed to work well within enclaves and is used by projects like [CCF](https://github.com/microsoft/CCF/)
that have high thoroughput requirements. CCF has observed the following performance improvements with `snmalloc`:

```
CCF SmallBank benchmark, 1m transactions, Standard_DC8 VM:

OpenEnclave with dlmalloc:

1 worker thread: 35k Tx/s
2 worker threads: 37k Tx/s
3 worker threads: 29k Tx/s
4 worker threads: 27k Tx/s

OpenEnclave with snmalloc:

1 worker thread: 39k Tx/s
2 worker threads: 77k Tx/s
3 worker threads: 110k Tx/s
4 worker threads: 115k Tx/s
5 worker threads: 143k Tx/s
6 worker threads: 156k Tx/s
```

## Plugging in a Custom Allocator

Plugging in a custom allocator is a straight-forward process that involves two steps:
1. **Configuring the heap size appropriately for the allocator.**

    High-performance, thread-aware allocators have minimum memory requirements that may be constant (e.g.: tcmalloc)
    or that may be per enclave thread (snmalloc).
    The size of the enclave's heap must be configured to meet this
    minimum requirement.

    This sample uses `oesnmalloc` which is a version of `snmalloc` that works within enclaves.
    `oesnmalloc` requires at least 256 KB per thread and therefore the
    enclave is configured appropriately in [enclave/allocator_demo.conf](enclave/allocator_demo.conf).
    ```
    # snmalloc requires at least 256 KB per enclave thread.
    # Given 16 enclave threads (NumTCS), this implies
    #    minimum heap size = (256 * 1024 * 16) / 4096 = 1044 pages.
    # The heap size (8192 pages) is well above the minimum requirement,
    # and accounts for the large number of allocations performed by
    # each enclave thread in the sample.
    NumHeapPages=8192
    NumTCS=16
    ```

2. **Linking the allocator.***

   The allocator must be plugged-in by specifying it in the linker line before `oelibcxx`, `oelibc` and `oecore` libraries.
   This causes the pluggable allocator implementation to be chosen by
   the linker instead of the default allocator implementation.

   In [enclave/CMakeLists.txt](enclave/CMakeLists.txt), `oesnmalloc` is thus specified before `oelibcxx` library:
   ```
    target_link_libraries(enclave_custom
        openenclave::oeenclave
        # Specify pluggable allocator library
        openenclave::oesnmalloc
        openenclave::oelibcxx)
   ```

## Making an allocator Pluggable

Making an allocator pluggable is also a two step process, that is however quite advanced.

1. **Make the allocator compile/work within enclaves.**

    The first step is to make sure that the allocator can be compiled for use within the enclave.
    This involves eliminating use of platform features like `mmap` that are not available within the enclaves.

2. **Implement the Pluggable Allocators Interface.**

    An allocator can be made pluggable by implementing the callback functions declared in
    [openenclave/include/advanced/allocator.h](https://github.com/openenclave/openenclave/blob/master/include/openenclave/advanced/allocator.h).

    [Pluggable Allocators Design Document](https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/PluggableAllocators.md)
	describes the design of pluggable allocators.

    Refer to the following examples when implementing replacement functions for any
    other allocator that you may want to port and make pluggable:
    - [Replacement functions for snmalloc](https://github.com/openenclave/openenclave/blob/3d7c177c7179483ceba49d0c4c0edc24039ea255/3rdparty/snmalloc/allocator.cpp#L27-L52)
    - [Replacement functions for dlmalloc](https://github.com/openenclave/openenclave/blob/3d7c177c7179483ceba49d0c4c0edc24039ea255/3rdparty/dlmalloc/allocator.c#L66-L117)


## About the Sample

This sample uses a memory allocation benchmark to demonstrate pluggable allocators.

Two enclaves are created:
1. `enclave_default` that uses the default allocator.
2. `enclave_custom` that uses a custom allocator (oesnmalloc).

The host loads the first enclave, runs a benchmark that performs memory allocations,
prints the elapsed time, and unloads the enclave.
Then the host loads the second enclave, runs the same benchmark, prints the elapsed time,
and unloads the enclave.
The elapsed times give an indication of how much speed up the custom allocator provides over
the default allocator.

The host then repeats the benchmarks on the two enclaves, but increases the number of threads
each time, until the maximum number of threads (15) is reached.

It can be observed that the custom allocator scales nicely with multiple threads whereas the
default allocator does not.

Note: The benchmark may not mirror the allocation pattern of your enclaves. Therefore the user
is strongly encouraged to perform their own benchmarks to choose the allocator that is most
appropriate for their application.

To build the sample

```bash
$ mkdir build
$ cd build
$ cmake .. -DCMAKE_BUILD_TYPE=Release
$ make
```

On the test machine, running the sample produces the following output that shows
that `oesnmalloc` shows a speed up factor between 2X and 35X depending upon the
number of threads.

```
$ make run
Configuration:
                                mode = hardware
        num-allocations (per-thread) = 100000
                 max-allocation-size = 16384 bytes
num-threads = 1:
      dlmalloc   (default allocator) =    9 milliseconds
    oesnmalloc (pluggable allocator) =    6 milliseconds

num-threads = 2:
      dlmalloc   (default allocator) =   39 milliseconds
    oesnmalloc (pluggable allocator) =   10 milliseconds

...
...
...

num-threads = 12:
      dlmalloc   (default allocator) =  974 milliseconds
    oesnmalloc (pluggable allocator) =   35 milliseconds

num-threads = 13:
      dlmalloc   (default allocator) = 1106 milliseconds
    oesnmalloc (pluggable allocator) =   35 milliseconds

num-threads = 14:
      dlmalloc   (default allocator) = 1235 milliseconds
    oesnmalloc (pluggable allocator) =   40 milliseconds

num-threads = 15:
      dlmalloc   (default allocator) = 1469 milliseconds
    oesnmalloc (pluggable allocator) =   40 milliseconds

num-threads = 16:
      dlmalloc   (default allocator) = 1565 milliseconds
    oesnmalloc (pluggable allocator) =   43 milliseconds
```


## About the EDL

The [EDL](allocator_demo.edl) contains just a single ECALL `enclave_thread`:

```c
    trusted {
        public void enclave_thread(
	        uint64_t num_allocations,      // Number of allocations to perform
	        uint64_t max_allocation_size); // Maximum size of each allocated object
    };
```

`num_allocations` specifies the number of allocations to perform (default = 100000).

`max_allocation_size` specified the maximum size of each allocation (default = 16 KB).

## About the enclaves

The enclaves are configured with a heap-size of `8192` pages.
This is sufficient for both `dlmalloc` and `oesnmalloc` benchmarks.

[enclave/allocator_demo.conf](enclave/allocator_demo.conf):
```
NumHeapPages=8192
NumTCS=16
```

`enclave_default` just links agains `oelibcxx` and hence uses the default allocator.
`enclave_custom` plugs in `oesnmalloc` by specifying it before `oelibcxx` in the linker dependencies.

[enclave/CMakeLists.txt](enclave/CMakeLists.txt)
```
  target_link_libraries(enclave_default
    openenclave::oeenclave
    openenclave::oelibcxx)

  target_link_libraries(
    enclave_custom openenclave::oeenclave
    # Specify pluggable allocator library
    openenclave::oesnmalloc
    openenclave::oelibcxx)
```

Both the enclaves share the implementation the ECALL `enclave_thread`
defined in [enclave/enc.cpp](enclave/enc.cpp).

A queue of length `QUEUE_LENGTH` (15) items is created and initialized to NULLs.
```c
    std::queue<void*> allocations;

    // Fill queue with null pointers.
    for (uint32_t i = 0; i < QUEUE_LENGTH; ++i)
        allocations.push(nullptr);
```

Every time an object is allocated, it is pushed to the queue.
The size of the object is randomly chosen between `0` and `max_allocation_size`.

Before an object is added to the queue, the first item in the queue
is popped and freed. Using a queue in this manner ensures that there are
`QUEUE_LENGTH` objects alive at a given time in a thread.
Keeping multiple objects alive mirrors real-world applications in which many objects
exist in memory at the same time.

```c
    for (uint64_t i = 0; i < num_allocations; ++i)
    {
        // Pop item from queue.
        void* ptr = allocations.front();
        allocations.pop();

        // allocate object and add to queue.
        uint64_t bytes = uint64_t(rand()) % max_allocation_size;
        allocations.push(malloc(bytes));

        // Free last popped item.
        free(ptr);
    }
```

## About the host

The [host](host/host.cpp) expects the signed versions of both the enclaves
to be passed as the first two command line arguments.
It also supports command line parameters `--simulate`, `--num-allocations`,
 `--max-threads` and `--max-allocation-size` to enable configuring the
benchmark.

```c
static void _print_usage_and_exit(const char* argv[])
{
    printf(
        "usage:\n"
        "    %s <default-enclave-path> <custom-enclave-path> "
        "[--simulate] "
        "[--num-allocations <value>] "
        "[--max-threads <value>]"
        "[--max-allocation-size <value>]\n",
        argv[0]);
    exit(1);
}
```

On each enclave, the host calls the `_run_benchmark` function to perform
the allocation benchmark. `_run_benchmark` function first creates the enclave
and then launches multiple threads that invoke the `enclave_thread` ECALL.
It measures and prints the elapsed time.

```c
    // Launch enclave threads that perform lots of memory allocations and
    // deallocations. Measure and print the elapsed time.
    {
        auto start_time = high_resolution_clock::now();

        vector<thread> threads(num_threads);
        for (size_t i = 0; i < threads.size(); ++i)
            threads[i] = std::thread([enclave]() {
                enclave_thread(enclave, _num_allocations, _max_allocation_size);
            });

        for (size_t i = 0; i < threads.size(); ++i)
            threads[i].join();

        auto end_time = high_resolution_clock::now();
        auto elapsed =
            duration_cast<milliseconds>(end_time - start_time).count();

        printf("    %32s = %4lu milliseconds\n", allocator_name, elapsed);
    }
```

The host repeats the benchmark, and each time increases the number of threads.
This demonstrates how thread-aware allocators like `snmalloc` scale better
in allocation intensive multi-threaded enclaves.

```c
    for (uint32_t num_threads = 1; num_threads <= _max_threads;
         num_threads += 1)
    {
        printf("num-threads = %u:\n", num_threads);
        _run_benchmark(argv[1], "dlmalloc   (default allocator)", num_threads);
        _run_benchmark(argv[2], "oesnmalloc (pluggable allocator)", num_threads);
        printf("\n");
    }
```
