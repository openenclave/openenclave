# The debug malloc sample

- Introduction about debug malloc.
- Demonstrate how to enable debug malloc through compiling options.
- Explanation and sample of debug malloc public APIs.

## Introduction

Debug malloc is a tool that helps identifying memory leaks in enclaves. The
main logic of debug malloc is as follows.

- Whenever memory is allocated, debug malloc captures the callstack and
associates it with the allocated memory. Additionally, debug malloc sets the
contents of the allocated memory to zero.

- Whenever memory is freed, all bytes are set to 0x0D to help
detect access of freed memory. It also frees the associated callstack
information.

- When an enclave terminates, debug malloc prints information about leaks---
those objects that have been allocated, but not freed.

There are two major problems
which memory leak detection can help to address:

- A developer wants to track all memory allocations throughout the execution of an enclave
  and to determine if any of these allocations were leaked.
  We call this "global detection".

- A developer wants to track memory allocations in a specific part of the enclave's
  execution that he or she can specify at the source code level. We call this "local detection".

## Global detection

Debug malloc is available as a separate library
oelibdebugmalloc.a, then there are two options to enable the global detection.

### Global default option

The "USE_DEBUG_MALLOC" define controls the global default. It is set to "ON" in
debug mode by default. You can modify this default option according to the
need, such as changing it to "ON" in release mode or changing it to "OFF" in
debug mode.

Please note that this option only works if you are building OE from source
code that this option is only valid in the OE project and not exported.
Additional, as a global option it will add the "-loedebugmalloc" option to all
the enclave targets in the OE project. If you are not building OE from source
or just want to apply this library to specific enclaves, please check the next
"custom option".

### Custom option

Since oelibdebugmalloc.a is a separate library, you can turn on debug malloc
per enclave while the default option is "OFF".

To use debug malloc, link oelibdebugmalloc.a into your
enclaves explicitly. This can be done by
```
      cmake:
      target_link_libraries(enclave openenclave::oedebugmalloc
              openenclave::oeenclave openenclave::oelibc)

      make:
      LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --libs)
      LDFLAGS_CUSTOM=$(subst -loelibc, -loedebugmalloc -loelibc, $(LDFLAGS))
      $(CC) -o debugmallocenc debugmalloc_t.o enc.o $(LDFLAGS_CUSTOM)

```

Please note that oedebugmalloc must be specified in the linker line before
`oelibcxx`, `oelibc` and `oecore` libraries to make sure the related functions
are loaded from oedebugmalloc.

Through the global default option or the custom option, an enclave can be linked
against oedebugmalloc and the global detection is enabled automatically. If
there are any memory leaks since enclave creation, during the enclave
termination all the leaks will be printed to the stdout. Please check the
Example paragraphs for the expected output.

## Local detection

The following APIs are provided in the header file `debugmalloc.h`.

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
supposed to be the subset of the result of global detection.

## Example
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
    void *buffer1, *buffer2, *buffer3;
    uint64_t count;
    char* report;

    oe_assert(oe_debug_malloc_tracking_start() == OE_OK);
    buffer1 = oe_malloc(4096);
    oe_assert(oe_debug_malloc_tracking_stop() == OE_OK);
    if (oe_debug_malloc_tracking_report(&count, &report) == OE_OK)
    {
        printf("There are %d un-freed objects reported:\n%s\n", count, report);
        oe_free(report);
    }

    oe_assert(oe_debug_malloc_tracking_start() == OE_OK);
    buffer2 = oe_malloc(4096);
    oe_assert(oe_debug_malloc_tracking_stop() == OE_OK);

    oe_assert(oe_debug_malloc_tracking_start() == OE_OK);
    buffer3 = oe_malloc(4096);
    oe_assert(oe_debug_malloc_tracking_stop() == OE_OK);
    if (oe_debug_malloc_tracking_report(&count, &report) == OE_OK)
    {
        printf("There are %d un-freed objects reported:\n%s\n", count, report);
        oe_free(report);
    }

    oe_free(buffer1);
    oe_free(buffer2);
    oe_free(buffer3);

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
Please make sure the report is released after each calling of
oe_debug_malloc_tracking_report(), since it incurs allocation at every turn.

For the local detection, the expected output result are 1 and 3 leaks for each
report respectively:
```
There are 1 un-freed objects reported:
oe_debug_malloc(): 7efc950f1f90
oe_malloc(): 7efc950f3463
enclave_hello(): 7efc9501804d
ecall_enclave_hello(): 7efc95003762
oe_handle_call_enclave_function(): 7efc95126cd9
_handle_ecall(): 7efc95128bae
__oe_handle_main(): 7efc951284ef
oe_enter(): 7efc95129e6c


There are 3 un-freed objects reported:
oe_debug_malloc(): 7efc950f1f90
oe_malloc(): 7efc950f3463
enclave_hello(): 7efc950183d6
ecall_enclave_hello(): 7efc95003762
oe_handle_call_enclave_function(): 7efc95126cd9
_handle_ecall(): 7efc95128bae
__oe_handle_main(): 7efc951284ef
oe_enter(): 7efc95129e6c

oe_debug_malloc(): 7efc950f1f90
oe_malloc(): 7efc950f3463
enclave_hello(): 7efc95018265
ecall_enclave_hello(): 7efc95003762
oe_handle_call_enclave_function(): 7efc95126cd9
_handle_ecall(): 7efc95128bae
__oe_handle_main(): 7efc951284ef
oe_enter(): 7efc95129e6c

oe_debug_malloc(): 7efc950f1f90
oe_malloc(): 7efc950f3463
enclave_hello(): 7efc9501804d
ecall_enclave_hello(): 7efc95003762
oe_handle_call_enclave_function(): 7efc95126cd9
_handle_ecall(): 7efc95128bae
__oe_handle_main(): 7efc951284ef
oe_enter(): 7efc95129e6c

```

For the global detection, Since this sample has no memory leak at the point of
enclave termination, the result is "OE_OK". However, if one of these allocation
is not freed, the result should be "OE_MEMORY_LEAK". For example, if line 46 at
`enclave/enc.c` is removed, the global detection can catch the leak and then
the return value is "OE_MEMORY_LEAK":
```
2020-10-09T15:41:50-0700.150188Z [(H)ERROR] tid(0x7f255ec012c0) | :OE_MEMORY_LEAK [/home/alvin/openenclave/host/sgx/create.c:oe_terminate_enclave:1132]

```

## Note

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

## Build and run

Open Enclave SDK supports building the sample on both Linux and Windows.
Linux supports two types of build systems, GNU Make with `pkg-config` and CMake,
while Windows supports only CMake.

### Linux

### Source the openenclaverc file

Information on this can be found in [Sourcing the openenclaverc file](../BuildSamplesLinux.md#source-the-openenclaverc-file)

#### CMake

This uses the CMake package provided by the Open Enclave SDK.

```bash
cd debugmalloc
mkdir build && cd build
cmake ..
make run
```

#### GNU Make

```bash
cd debugmalloc
make build
make run
```

### Windows

### Set up the environment

Information on this can be found in [Steps to build and run samples](../BuildSamplesWindows.md#steps-to-build-and-run-samples)

#### CMake

```cmd
mkdir build && cd build
cmake .. -G Ninja -DNUGET_PACKAGE_PATH=C:\oe_prereqs
ninja
ninja run
```

#### Note

The debugmalloc sample can run under OE simulation mode.

On Linux, to run the debugmalloc sample in simulation mode from the command like, use the following:

```bash
host/debugmallochost ./enclave/debugmallocenc.signed --simulate
```

On Windows, to run the debugmalloc sample in simulation mode from the command like, use the following:

```cmd
host/debugmallochost ./enclave/debugmallocenc.signed --simulate
```
