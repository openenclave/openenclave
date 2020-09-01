Proposal to enable debug malloc for end users
===

# Motivation

Debug malloc is an internal tool that helps identifying memory leaks in
enclaves. It is turned on by default in the debug builds of the OE SDK.

The main logic of debug malloc is as follows.

- Whenever memory is allocated, debug malloc captures the callstack and
associates it with the allocated memory. Additionally, debug malloc sets the
contents of the allocated memory to zero.

- Whenever memory is freed, it clears the contents to a fixed pattern to help
detect access of freed memory. It also frees the associated callstack
information.

- When an enclave terminates, debug malloc prints information about leaks---those objects that have been allocated,
  but not freed.

Debug malloc is performance intensive and is therefore not compiled into the SDK release.

There have been requests from users that debug malloc be made available so that they can
identify memory leaks within an enclave. Commonly used memory detection tools like Valgrind do not
work within enclaves since they cannot access enclave memory.

According to the user's developing experience, there are two major problems
which the memory leaking detection can help to address:

- A developer wants to track all memory allocations throughout the execution of an enclave
  and to determine if any of these allocations were leaked.
  We name it "global detection".

- A developer wants to track memory allocations in a specific part of the enclave's
  execution that he or she can specify at the source code level. We name it "local detection".

Open Enclave already provides some support for "global detection", so this
document will focus on the design for supporting "local detection."

# User Experience

## Global detection

Debug malloc will be shipped to the users as a separate library
oelibdebugmalloc.a, then there are two options to enable the global detection.

### Global default option

The "USE_DEBUG_MALLOC" define controls the global default. Now we already set "USE_DEBUG_MALLOC"
to "ON" in debug mode by default. Users can modify this default option
according to the need, such as changing it to "ON" in release mode or changing it
to "OFF" in debug mode.

Please note that this option only works if you are building OE from source
code that this option is only valid in the OE project and not exported.
Additional, as a global option it will add the "-loedebugmalloc" option to all
the enclave targets in the OE project. If you are not building OE from source
or just want to apply this library to specific enclaves, please check the next
"custom option".

### Custom option

Since oelibdebugmalloc.a is a separate library, users can turn on debug malloc
per enclave while the default option is "OFF".

To use debug malloc, users will have to link oelibdebugmalloc.a into their
enclaves explicitly. This can be done by
```
      cmake:
      target_link_libraries(user-enclave oelibc oedebugmalloc oeenclave)

      make:
      LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --libs)
      LDFLAGS_CUSTOM=$(subst -loelibc, -loedebugmalloc -loelibc, $(LDFLAGS))
      $(CC) -o user-enclave user-enc.o $(LDFLAGS_CUSTOM)

```

For the global detection, if there is any memory leak during the enclave's
life cycle, an error code "OE_MEMORY_LEAK" will be raised during the enclave
termination. This means it not only checks the users' enclave application,
but also covers the SDK's allocations on the enclave side.

## Local detection

Currently, debug malloc prints leaks only during enclave termination.
However, users would like to isolate and track specific memory allocations.
To achieve this, the following APIs are provided in a new published header `debugmalloc.h`.

- `oe_result_t oe_debug_malloc_tracking_start(void)`

  Starts tracking allocations that will be displayed in report. Subsequent
  calls to start without a preceding stop will be ignored and return value is
  "OE_UNEXPECTED".

- `oe_result_t oe_debug_malloc_tracking_stop(void)`

  Stops tracking allocations that will be displayed in report. Multiple calls
  to stop without another start are treated as no-ops and return value is
  "OE_UNEXPECTED".

- `    oe_result_t oe_debug_malloc_tracking_report(
        uint64_t* out_object_count,
        char** report)
  `

  Report the leaks, including the number and details of allocations that have
  not been freed since start was called. If called after stop, it reports the
  set of allocations that were not freed while tracking is turned on, even if
  they might have been freed between the calls to stop and report. If called
  before the earliest start, the report includes nothing.

Please note that the timing and sequences of calling of these functions is
important:

- The starting and stopping tracking must cover the coupled malloc/free
operations, which means start tracking before malloc and also stop tracking
after free, or the report will definitely trigger false alarms that some
reported objects actually are freed after stopping tracking.

- oe_debug_malloc_tracking_stop() can only been called after calling
oe_debug_malloc_tracking_start(), and oe_debug_malloc_tracking_start() can be
called at the beginning or after calling oe_debug_malloc_tracking_stop(). While
the calling sequence following this rule, the return values are OE_OK. Return
value "OE_UNEXPECTED" means the sequence is not expected.

Regardless the execution and output of these state switching functions,
oe_debug_malloc_tracking_report() covers all the leaks happened during the
tracking state cumulatively.

```
      stop()  |--------------|  start() |--------------|  start()
   |--------->|              |--------->|              |----------|
   |          | not tracking |          |   tracking   |          |
   |----------|              |<---------|              |<---------|
              |--------------|  stop()  |--------------|
```

- oe_debug_malloc_tracking_start() and oe_debug_malloc_tracking_stop() can be
called many times:

```
  |----code1--|-----------|----code2--|--|----code3--|
  start1->stop1->report1->start2->stop2->start3->stop3->report3
```

In this case report1 only covers code1, and report3 covers code1, code2 and
code3.

Please also note that these public APIs only affect the result of local
detection. The result of global detection is independent of these APIs. While
the calling of these APIs follow the rules, the result of local detection is
supposed to be the subset of result of global detection.

# Implementation

The debug malloc employs a linked list to make a record of all memory operations.
So, for the local detection, we can make use of the fulfilled record system.

```c
struct header
{
    /* Contains HEADER_MAGIC1 */
    uint64_t magic1;

    /* Headers are kept on a doubly-linked list */
    header_t* next;
    header_t* prev;

    /* The alignment passed to memalign() or zero */
    uint64_t alignment;

    /* Size of user memory */
    size_t size;

    /* Return addresses obtained by oe_backtrace() */
    void* addrs[OE_BACKTRACE_MAX];
    uint64_t num_addrs;

    /* Option if current object is tracked */
    bool local_tracking;

    /* Padding to make header a multiple of 16 */
    uint8_t padding[7];

    /* Contains HEADER_MAGIC2 */
    uint64_t magic2;

    /* User data */
    uint8_t data[];
};
```

We also add a variable
```c
bool oe_use_debug_malloc_tracking = false;
```
which will be changed by oe_debug_malloc_tracking_start() and
oe_debug_malloc_tracking_stop(). While doing the allocation, the objective's
`local_tracking` is marked as `oe_use_debug_malloc_tracking`, then
oe_debug_malloc_tracking_report() can get the number of all the not yet freed
objects.

# Sample

```c
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/debugmalloc.h>
#include <stdio.h>

// Include the trusted debugmalloc header that is generated
// during the build. This file is generated by calling the
// sdk tool oeedger8r against the debugmalloc.edl file.
#include "debugmalloc_t.h"

// This is the function that the host calls. It prints
// a message in the enclave before calling back out to
// the host to print a message from there too.
void enclave_hello()
{
    void* buf1, * buf2, * buf3;
    uint64_t num;
    char* report;

    oe_assert(oe_debug_malloc_tracking_start() == OE_OK);
    buf1 = oe_malloc(4096);
    oe_assert(oe_debug_malloc_tracking_stop() == OE_OK);
    if (oe_debug_malloc_tracking_report(&num, &report) == OE_OK)
    {
        printf("There are %d un-freed objects reported:\n%s\n", num, report);
    }

    oe_assert(oe_debug_malloc_tracking_start() == OE_OK);
    buf2 = oe_malloc(4096);
    oe_assert(oe_debug_malloc_tracking_stop() == OE_OK);

    oe_assert(oe_debug_malloc_tracking_start() == OE_OK);
    buf3 = oe_malloc(4096);
    oe_assert(oe_debug_malloc_tracking_stop() == OE_OK);
    if (oe_debug_malloc_tracking_report(&num, &report) == OE_OK)
    {
        printf("There are %d un-freed objects reported:\n%s\n", num, report);
    }

    oe_free(buf1);
    oe_free(buf2);
    oe_free(buf3);
    oe_free(report);

    // Call back into the host
    oe_result_t result = host_hello();
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "Call to host_hello failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
    }
}
```
For the local detection, the expected output result are 1 and 3 leaks for each
report, respectively.

For the global detection, Since this sample has no memory leak at the point of
enclave termination, the result is "OE_OK". If one of the `oe_free` calls is missing, the
result should be "OE_MEMORY_LEAK".

# Note

To improve users' experience, we add the runtime functions that users can use
to locate the memory leaks. However, the local detection implementation is not
thread-safe.

- For local detection, the tracking state is defined by the global variable
`oe_use_debug_malloc_tracking`, which means if the new public functions
execute on different threads at the same time, the results may be inaccurate.

- The thread-safe concern is confined to local detection only. Debug malloc
does not require thread-aware allocators to behave differently to work with
debug malloc. The global detection is thread-safe and accurate.

- Since debug malloc is a wrapper around the memory allocator, it is fully
composable with a pluggable OE allocator, and it does not require any change to
the OE allocators for the new features. Also, the underlying allocator
execution on independent threads will not affect the result of debug malloc.

Yet debug malloc is a useful tool for developers. Thus we hope the new feature
can help the development of enclave applications.
