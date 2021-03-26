Debugger Support for Multi-Module Enclaves
====

This document describes extensions to the
[Debugger Contract](/include/openenclave/internal/debugrt/host.h) to support
debugging enclaves comprised of multiple modules.

Introduction
------------

Currently, enclaves are built as a single module - a special elf executable that
is loaded by OE SDK's enclave loader. Since enclaves are loaded by a special
loader, unlike normal executables and shared libraries that are loaded by the
platform's loader (e.g /lib64/ld-linux-x86-64.so.2), the debugger does not
natively know how to load symbols for enclaves. Therefore, the host side OE SDK
runtime invokes following functions to enable the debugger to locate
and debug an enclave. The following functions perform necessary house-keeping
tasks and then call hook functions to interact with the debugger.

- `oe_result_t oe_debug_notify_enclave_created(oe_debug_enclave_t* enclave)`

  This function is called immediately after an enclave has been loaded into
  memory, but before it has been initialized/begun execution. The debugger uses
  the  `oe_debug_enclave_t` structure to load the symbols and mark a region of
  program memory as being taken up by the enclave:

  ```c

    typedef struct _debug_enclave_t
    {
        uint64_t magic;

        uint64_t version;

        // Pointer to next enclave
        // See "Attaching the debugger" section below
        struct _debug_enclave_t* next;

        const char* path;
        uint64_t path_length;

        const void* base_address;
        uint64_t size;

        // Enclave's TCS information.
        struct _sgx_tcs** tcs_array;
        uint64_t tcs_count;

        uint64_t flags;
    } oe_debug_enclave_t;

  ```
  The `path` and `path_length` fields tell the debugger the path to the
  enclave's ELF binary. The elf binary is expected to contain the debugging
  information, if any, for the enclave. `oegdb` currently does not support
  debugging enclaves whose debugging information has been stripped and moved to
  a separate .dbg file.

  The `base_address` field tells the debugger the memory address at which the
  enclave has been loaded. The `size` field is not that important since the
  debugger can figure out the size of relevant sections fom the ELF binary.
  The field is retained for making `oe_debug_enclave_t` complete for
  describing an enclave. The debugger associates the memory region
  `[base_address, base_address+size)` with the enclave.

- `oe_result_t oe_debug_notify_enclave_terminated(oe_debug_enclave_t* enclave)`

  This function is called immediately after an enclave has been terminated and
  its memory has been deallocated. The debugger unloads the symbols for the enclave
  and dissociates the memory region from the enclave.

The debugger gains control and responds to the above notifications in the
following ways:

- Linux

  The debugger sets hidden breakpoints in the hook functions associated with
  the above notifications.
  `oe_debug_notify_enclave_created` performs necessary house-keeping tasks
  and then calls the following empty hook function:
  ```c
  OE_EXPORT void oe_debug_enclave_created_hook(
      const oe_debug_enclave_t* enclave)
  {
  }
  ```

  Similary, `oe_debug_notify_enclave_terminated` performs necessary
  house-keeping tasks and calls `oe_debug_notify_enclave_terminated_hook`:
  ```c
  OE_EXPORT void oe_debug_enclave_terminated_hook(
      const oe_debug_enclave_t* enclave)
  {
  }
  ```

  These hook functions are exported so that the debugger can find them even
  without debug symbols, and set hidden breakpoints. When these functions
  are called, the breakpoints are hit and the debugger gets control.
  The debugger then reads the `oe_debug_enclave_t` parameter to handle the
  notification.

- Windows

  From Visual Studio Debugger team:
  "In Windows, symbols are almost always found in separate PDB files instead of
  being embedded within the DLL. And it is easy to get into situations where
  symbols are not available. That makes relying on the debugger setting
  breakpoints (via symbol data) a lot more fragile."
  The debugger is instead notified of events by raising exceptions using the
  `RaiseException` API.

  `oe_debug_enclave_created_hook` raises the following exception:

  ```c
        ULONG_PTR args[1] = {(ULONG_PTR)enclave};
        RaiseException(
          OE_DEBUGRT_ENCLAVE_CREATED_EVENT,
          0, // dwFlags
          1, // number of args
          args);
  ```

  whereas `oe_debug_enclave_terminated_hook` raises:

  ```c
        ULONG_PTR args[1] = {(ULONG_PTR)enclave};
        RaiseException(
          OE_DEBUGRT_ENCLAVE_TERMINATED_EVENT,
          0, // dwFlags
          1, // number of args
          args);
  ```

  The Windows debuggers (Visual Studio and WinDbg) consume the
  `OE_DEBUGRT_ENCLAVE_CREATED_EVENT` and `OE_DEBUGRT_ENCLAVE_TERMINATED_EVENT`
  events. Upon receiving the events, the debuggers invoke the appropriate
  infrastructure to enable debugging the module.

### Attaching the debugger

It is possible to attach the debugger to an application that has already created
enclaves. In such a scenario, the debugger has missed the chance to be notified
of enclave creation since it wasn't debugging the program when the enclave was
created. To allow the debugger to load symbols for enclave after the fact, the
host-side runtime maintains a global list of loaded enclaves:

When an enclave is loaded, it is added to the list, and when an enclave is
unloaded, it is removed from the list.

```c
OE_DEBUGRT_EXPORT extern oe_debug_enclave_t* oe_debug_enclaves_list;
```

The `oe_debug_enclave_list` is exported so that the debugger can find this list
without symbols. Upon attaching to a program, the debugger is expected to iterate
through this list and load symbols for the enclaves in the list. The debugger
will process the list only once - when attaching to a program or when loading a
memory dump (see "Analyzing crash-dumps" below).

Adding an enclave to `oe_debug_enclaves_list` and notifying the debugger via the
hook functions are not atomic operations, and the order in which they are
performed lead to different edge-cases.

- Order 1
  1. Add enclave to oe_debug_enclaves_list
  2. Call oe_debug_enclave_created_hook.

  The debugger may attach to the running program between steps 1 and 2. In this
  case, upon attaching, the debugger would process the list and load symbols for
  the enclave. The debugger will be notified again about the same enclave when
  the hook is called in step 2. This leads to double-notification.
  
- Order 2
  1. Call oe_debug_enclave_created_hook.
  2. Add enclave to oe_debug_enclaves_list

  The debugger may attach to the running program between steps 1 and 2. In this
  case, the debugger has missed the hook when it was invoked. The debugger 
  processes the global list which does not contain the enclave. Later when
  the enclave is added to the list in step 2, the debugger does not reprocess
  the list. This leads to a lost enclave.
  
To avoid lost enclaves, Order 1 is preferred and the debugger is expected to
ignore double-notifications for enclave creation.

Similarly, during enclave termination, the enclave is first removed from the list
and then `oe_debug_enclave_terminated_hook` is called. This ensures that
even if the debugger attaches between the two steps, it would not accidentally
retain and enclave that has been terminated.

### Analyzing crash-dumps

Loading up a crash-dump is quite similar to attaching to a running program, for the
purposes of this discussion. If the global enclave list has been captured in the
dump and is not corrupt, then the debugger can easily find it in the dump since
it is an exported symbol. It can then load the debug symbols for the enclaves
by processing the list.

Note: At this point only WinDbg locks down crash-dump support for enclaves.
Though it might work in oedgb and VS, it has not been extensively tested or locked
down.

Use-cases for Multi-Module Enclaves
-----------------------------------

There are a few implementations of multi-module enclaves based on OE SDK:

- [SGX LKL](https://github.com/lsds/sgx-lkl)

  This project runs a modified Linux kernel within an enclave and supports running
  enclaves comprised of executables and shared libraries. This project supports
  debugging of multi-module enclaves.

  For reference, here is the GDB extensions module for SGX LKL.
  `__gdb_hook_load_debug_symbols` and `LoadLibraryBreakpoint` show how
  internal breakpoint and a "hook" (notification callback) function is used to
  notify the debugger about libraries (modules).
  https://github.com/lsds/sgx-lkl/blob/3038804995ff40612fda72b3f20210ceb1339ea1/tools/gdb/sgx-lkl-gdb.py#L94

- [feature.openlibos](https://github.com/openenclave/openenclave/tree/feature.openlibos)

  This branch of OE SDK runs a library OS within an enclave. It also supports
  enclave comprised of multiple executables and shared libraries.

  For reference, here are the additions to oegdb to support multi-module
  debugging. Note the use of breakpoints (e.g LibraryLoadBreakpoint) and
  notification hook functions (e.g: oe_notify_debugger_library_load)
  https://github.com/openenclave/openenclave/blob/cf9426d83125a47c2455d3de929957f0dd73f54e/debugger/pythonExtension/gdb_sgx_plugin.py#L285-L327


- [feature/dynamic_binding](https://github.com/openenclave/openenclave/tree/feature/dynamic_binding)

  This branch of OE SDK allows loading and running multi-module enclaves with
  the goal of permitting use of FIPS certified crypto modules. It also supports
  debugging multi-module enclaves.
  Here is the set of changes required to support multi-module loading.
  It is uses a quite similar strategy to the above implementations:
  https://github.com/openenclave/openenclave/commit/254ae94324b619861f58d0110a1affac37e5a2a4?branch=254ae94324b619861f58d0110a1affac37e5a2a4&diff=split


The debugger changes required to support multi-module enclaves are quite similar
in the above three implementations. The following proposal formally incorporates
the necessary debugger changes into the Debugger Contract.

Debugger Contract Extensions to Support Multi-Module Enclaves
-------------------------------------------------------------

The following `oe_debug_module_t` structure captures the information necessary
to debug a module:

```c

    typedef struct _debug_module_t
    {
        // Magic value at start of the structure.
        uint64_t magic;
        // Structure version.
        uint64_t version;

        // Next item in list of modules.
        struct _debug_module_t* next;

        // Path of module's ELF binary.
        char* path;
        uint64_t path_length;

        // Memory region where the enclave has been loaded.
        uint64_t base_address;
        uint64_t size;
    } oe_debug_module_t;

```

The `path` and `path_length` together specify the path of the module's ELF
binary. The `base_address` and `size` together specify the memory region
where the enclave has been loaded.

The following notification functions are used to notify the debugger about the
loading and unloading of a module. Just like enclave creation/termination
notification functions, the module load/unload notification functions perform
necessary house-keeping tasks and then call the corresponding hook functions.

- `oe_result_t oe_debug_notify_module_loaded(oe_debug_module_t* module)`

   This function is called by the SDK's host-runtime after a module has been
   loaded, but before it has been initialized. A module is initialized by invoking
   its constructor functions. It does not matter whether the module has been relocated
   or not before the debugger is notified about the module.

   In situations where a module may be dynamically loaded by an enclave, as is the case
   when SGX LKL/openlibos launch applications within the enclave, this notification
   function is called by the SDK's enclave-side runtime prior to the initialization
   of the module.

- `oe_result_t oe_debug_notify_module_unloaded(oe_debug_module_t* module)`

   This function is called by the SDK runtimes (host-side or enclave-side), after a
   module has been unloaded.

Debugger Handling of Module Load/Unload Notifications

- Linux
  Similar to enclave load/unload, the debugger sets internal breakpoints in
  corresponding hook functions.
  
  `oe_debug_notify_module_loaded` calls the following hook function after
  adding the module to the enclave's list of modules.
  ```c
  OE_EXPORT void oe_debug_module_loaded_hook(
      const oe_debug_module_t* module)
  {
  }
  ```

  The debugger sets a hidden breakpoint within the hook function. When the 
  breakpoint is triggered, debugger gets control and reads the module information
  from `oe_debug_module_t` structure. It loads the symbols for the module from
  the module's binary file which is expected to exist at the path specified by
  the `path` member in `oe_debug_module_t`. The debugger associates the memory
  region `[module-base-address, module-size)` with the module.
  
  
  `oe_debug_nofity_module_unloaded` calls the following hook function after
  removing the module from the enclave's list of modules.
  ```c
  OE_EXPORT void oe_debug_module_unloaded_hook(
      const oe_debug_module_t* module)
  {
  }
  ```
  The debugger sets a hidden breakpoint within the hook function. Upon getting
  control, the debugger dissociates the memory region `[module-base-address, module-size)`
  from the module, and unloads symbols for the module.


- Windows
  - Host Side

    The SDK host-side runtime uses the `RaiseException` Windows API to
    communicate with the debugger.
    `oe_debug_notify_module_loaded` raises the following exception:
    ```c

        ULONG_PTR args[1] = {(ULONG_PTR)module};
        RaiseException(
          OE_DEBUGRT_MODULE_LOADED_EVENT,
          0, // dwFlags
          1, // number of args
          args);

    ```

     whereas `oe_debug_notify_module_terminated` raises:
     ```c

        ULONG_PTR args[1] = {(ULONG_PTR)module};
        RaiseException(
          OE_DEBUGRT_MODULE_UNLOADED_EVENT,
          0, // dwFlags
          1, // number of args
          args);

    ```

  - Enclave side

    OE SDK enclaves are ELF binaries and therefore it is possible to use the
    same strategy on both Linux and Windows hosts.

    The two functions `oe_debug_notify_module_loaded` and
    `oe_debug_nofity_module_unloaded` are defined within enclaves
    as well. These function invoke the corresponding hook function
	`oe_debug_module_loaded_hook` and `oe_debug_module_unloaded_hook`.
	The hook functions are exported which allows the debugger to find and put
	breakpoints in then even if debug symbols are not present.
	
    For ELF enclaves, a function can be exported via
    `__attribute__((visibility=default))` where as for PE enclaves a
    function can be exported via `__dllexport`.

    The debugger is expected to read the parameter directly from the register
    as per the ABI. For ELF enclaves, the parameter is therefore available in
    `RDI` register whereas for PE enclaves the parameter is available in
    `RCX` register.

    An alternate approach of using `int $3` instruction to notify the
    Windows Debugger was discussed, but it was abandonded in favor of the above
    simpler implementation that works for both ELF and PE enclaves.

    A future goal would be to see if such an unified strategy could be used
    for all debugger notifications. That is, have the debugger use breakpoints
    in exported functions instead of `RaiseException`. Given the tight
    timelines involved for supporting FIPS crypto, investigating feasibility
    of an unified strategy shall be done at a later date.


The Debugger Contract version is incremented to `2` to reflect the addition of
the notification functions.

The host-side runtime will set [oe_debugger_contract_version](https://github.com/openenclave/openenclave/blob/6f94547dc920d70eb50ec8ca95ab65a17597364b/include/openenclave/internal/debugrt/host.h#L131)
to `2` during program startup. If an older debugger is used to debug a
multi-module enclave, then it will see that the contract version is `2`, and
advise the user to upgrade the debugger.

### Attaching the debugger

In order to enable the debugger to discover modules in the scenario where the
debugger is attached after the modules have been loaded, a list of modules
is maintained in the `oe_debug_enclave_t` data structure.

```c
typedef struct _debug_enclave_t
{
    uint64_t magic;

    uint64_t version;

    struct _debug_enclave_t* next;

    const char* path;
    uint64_t path_length;

    const void* base_address;
    uint64_t size;

    struct _sgx_tcs** tcs_array;
    uint64_t num_tcs;

    uint64_t flags;

    // New field added to the end
    oe_debug_module_t modules;
} oe_debug_enclave_t;
```
For each enclave in the global enclave list, the debugger will also process the
list of modules, if any, that has been loaded in addition to the
primary module. The debugger will process the `modules` list for an
enclave only once.


Similar to enclave creation/termination the order of adding/removing from the list
and invoking the hooks matters.

`oe_debug_notify_module_added` adds the module to the enclave's list of
modules and then invokes `oe_debug_module_loaded_hook`. The debugger is expected
to ignore double notifications for the module.

`oe_debug_notify_module_unloaded` removes the module from the enclave's list of
modules and then invokes `oe_debug_module_unloaded_hook`. 


### Analysing crash dumps

When a crash dump is loaded, the debugger will process the `modules` list
for each enclave in the global list, just as in the scenario when the debugger
is attached.

Authors
-------
- Anand Krishnamoorthi <anakrish@microsoft.com>
