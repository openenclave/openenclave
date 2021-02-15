Generalize the Calling Mechanisms of Enclave Functions
=====

Introduction
------------

Unlike typical function invocations via `call` instructions, TEE functions require
specialized calling mechanisms that allow an enclave and a host to interact with each other.
In the Open Enclave SDK, we use OCALLs to refer to the host-side functions for the
enclave to use and use ECALLs to refer to the enclave-side functions for the host to use.
The invocation of an OCALL/ECALL is analogous to message passing between two isolated entities via a channel.
Regardless of the type of a channel, which depends on the implementation of TEEs, invoking an ECALL/OCALL requires
a contract between the enclave and the host so that they know what messages to send and how to
interpret the messages they receive and to take actions accordingly.

This document describes the current implementation of ECALL invocations, its limitations, and the
proposal of code refactoring.

Current Implementation
-----------------------

**EDL**

The Open Enclave SDK currently uses the oeedger8r tool to generate the stub code of ECALLs and OCALLs
from an EDL file. The following example shows a file that defines an ECALL `sample_ecall()`
and an OCALL `sample_ocall()`.

```
// sample.edl
enclave
{
    trusted
    {
        public void sample_ecall();
    };

    untrusted
    {
        public void sample_ocall();
    };
}
```

Given the `sample.edl`, the oeedger8r generates `sample_u.c`/`sample_u.h` as the host-side stub
and `sample_t.c`/`sample_t.h` as the enclave-side stub.

**ECALL Invocation**

To invoke an ECALL, the host simply calls the `sample_ecall()` function by feeding
the pointer of the target `enclave` struct as the following code snippet.

```
result = sample_ecall(enclave);
```

The `sample_ecall()`, which is defined in `sample_u.c`, performs a series of checks,
marshals the arguments, and invokes the `oe_call_enclave_function()` function
as the following example.

```
if ((_result = oe_call_enclave_function(
        enclave,
        sample_fcn_id_sample_ecall,
        _input_buffer,
        _input_buffer_size,
        _output_buffer,
        _output_buffer_size,
        &_output_bytes_written)) != OE_OK)
    goto done;
```

The function, which is part of the `oehost` library, eventually dispatches the
provided arguments to the target enclave (specified by the `enclave`).
The argument `sample_fcn_id_sample_ecall` (with the `enum` type, defined in both
`sample_u.h` and `sample_t.h`) is used as an identifier that allows the enclave to
locate the corresponding ECALL. More specifically, `sample_t.c` defines
`__oe_ecalls_table` (an array of function pointers) and `__oe_ecalls_table_size` as follows.

```
oe_ecall_func_t __oe_ecalls_table[] = {
    (oe_ecall_func_t) ecall_sample_ecall
};

size_t __oe_ecalls_table_size = OE_COUNTOF(__oe_ecalls_table);
```

Both of them are global variables that are linked by the `oecore` library
and are used in the `oe_handle_call_enclave_function()` function,
which processes every request of ECALLs. The following code snippet shows
how the function looks up the ECALL wrapper from the `__oe_ecalls_table`.

```
...
ecall_table.ecalls = __oe_ecalls_table;
ecall_table.num_ecalls = __oe_ecalls_table_size;

if (args.function_id >= ecall_table.num_ecalls)
    OE_RAISE(OE_NOT_FOUND);

func = ecall_table.ecalls[args.function_id];
...

// Call the function.
func(
    input_buffer,
    args.input_buffer_size,
    output_buffer,
    args.output_buffer_size,
    &output_bytes_written);
```

After looking up based on the function id (`sample_fcn_id_sample_ecall`),
`oe_handle_call_enclave_function()` calls into the wrapper function `ecall_sample_ecall()`(defined in `sample_t.c`).
The wrapper function performs a series of checks, unmarshals the arguments, and invokes
the ECALL implemented by the enclave with the following code snippet.

```
/* Call user function. */
pargs_out->_retval = sample_ecall(
);
```

At this point, an ECALL is successfully dispatched to the enclave.

Limitation
---------

The current implementations pose a limitation to the scenario where the
host instantiates different enclaves that use the same set of ECALLs
(i.e., importing the same EDL files).
Take the following case study for example.

**Case Study 1: Importing the same EDLs with different order**

Assume the OE SDK provides two EDL files that allow enclaves to opt-in as follows.

```
// common_1.edl
enclave
{
    trusted
    {
        public void common_1_ecall();
    };
}
```

```
// common_2.edl
enclave
{
    trusted
    {
        public void common_2_ecall_1();
        public void common_2_ecall_2();
    };
}
```

Consider two enclaves, `foo` and `bar`. Their EDL files are defined as follows.

```
// foo.edl
enclave
{
    from "common_1.edl" import *;
    from "common_2.edl" import *;

    trusted
    {
        public void foo_ecall();
    };
}
```

```
// bar.edl
enclave
{
    from "common_2.edl" import *;
    from "common_1.edl" import *;

    trusted
    {
        public void bar_ecall();
    };
}
```

Note that both the EDL files import the two SDK-provided EDL files but in
a different order. The resulting ECALL tables defined in the
corresponding `_t.c` and `_u.c` files will be as follows.

- `foo` ECALL table
  ```
  oe_ecall_func_t __oe_ecalls_table[] = {
      (oe_ecall_func_t) ecall_common_1_ecall,
      (oe_ecall_func_t) ecall_common_2_ecall_1,
      (oe_ecall_func_t) ecall_common_2_ecall_2,
      (oe_ecall_func_t) ecall_foo_ecall
  };
  ```
- `bar` ECALL table
  ```
  oe_ecall_func_t __oe_ecalls_table[] = {
      (oe_ecall_func_t) ecall_common_2_ecall_1,
      (oe_ecall_func_t) ecall_common_2_ecall_2,
      (oe_ecall_func_t) ecall_common_1_ecall,
      (oe_ecall_func_t) ecall_bar_ecall
  };
  ```

In addition, both `foo_u.c` and `bar_u.c` will implement same wrapper functions
of the three imported functions. Assuming that we use *weak symbol* to avoid the
duplication of the wrapper functions (i.e., only one implementation of the functions is picked),
the invocation of these ECALLs to both enclaves ends up using the same function ids.

See the following host-side code snippet for an example.
```
// ECALL to the enclave `foo`.
common_1_ecall(enclave_foo);

// ECALL to the enclave `bar`.
common_1_ecall(enclave_bar);
```

Since the host can have only one implementation of `ecall_common_1_ecall` (the wrapper function),
both invocations end up using the same function id, say `0`. However, this causes the mismatch
on the call into the enclave `bar` where the expected id should be `2`.

**Case Study 2: Selectively importing the ECALLs from same EDLs**

Another scenario that both two enclaves selectively import ECALLs from the same EDLs but the
selections are different.

```
// foo.edl
enclave
{
    from "common_2.edl" import *;

    trusted
    {
        public void foo_ecall();
    };
}
```

```
// bar.edl
enclave
{
    from "common_2.edl" import common_2_ecall_2;

    trusted
    {
        public void bar_ecall();
    };
}
```

The resulting tables will be as follows.
- `foo` ECALL table
  ```
  oe_ecall_func_t __oe_ecalls_table[] = {
      (oe_ecall_func_t) ecall_common_2_ecall_1,
      (oe_ecall_func_t) ecall_common_2_ecall_2,
      (oe_ecall_func_t) ecall_foo_ecall
  };
  ```
- `bar` ECALL table
  ```
  oe_ecall_func_t __oe_ecalls_table[] = {
      (oe_ecall_func_t) ecall_common_2_ecall_2,
      (oe_ecall_func_t) ecall_bar_ecall
  };
  ```

Clearly, we can see the conflict on the function id.

Proposed revision
-----------

The main goal of this proposal is to address the limitation that different enclaves on the
same host cannot import the same EDL files (i.e., using the same set of ECALLs).
To this end, this document proposes to refactor the ECALL calling mechanism as follows.

**Maintain Local and Global ECALL tables on the Host**

- Local Tables

  Given that the rule of importing `EDL` files is flexible, the resulting
  ECALL table is not deterministic; i.e., the same ECALL may have different ids
  across enclaves. To solve the problem, this document uses an idea of storing the
  list of ECALL id per enclave, which we refer to as local ECALL tables.
  The local table is declared as follows.

  ```
  typedef struct _oe_ecall_id_t
  {
     uint64_t id;
  } oe_ecall_id_t;

  typedef struct _oe_enclave
  {
     ...
     /* Per-edl ecall id table. */
     oe_ecall_id_t ecall_id_table[OE_ECALL_MAX];
     uint32_t ecall_id_table_size;
     ...
  } oe_enclave_t;
  ```

  The local table allows the host to retrieve the ECALL id per enclave instead
  of using the hard-coded id in the same ECALL across different enclaves.

- Global Table

  To guarantee the constant-time look-up, the host needs to use the same id to retrieve
  the ECALL id from the local table. To do so, the host additionally maintains a global
  table that keeps such ids to which we refer as global ids. The detailed design is as follows.

  - The global table is defined internally in the `oehost` as follows. The table stores the name
    of each ECALL and the index to each name is used as the global id.
    ```
    const char* _ecall_table[OE_ECALL_MAX];
    uint32_t _ecall_table_size;
    ```
  - The global table is updated during every initialization of a local table. More specifically,
    the list of ECALL names is added to the `_u.c` and is passed to the `oe_create_enclave`.
    ```
    typedef struct _oe_ecall_info_t
    {
        const char* name;
    } oe_ecall_info_t;

    /**** Trusted function names. ****/
    const oe_ecall_info_t __foo_ecall_info_table[] =
    {
        { "ecall_common_1_ecall" },
        { "ecall_common_2_ecall_1" },
        { "ecall_common_2_ecall_2" },
        { "ecall_foo_ecall" },
        { NULL }
    };
    ```
    ```
    oe_result_t oe_create_foo_enclave(
      const char* path,
      oe_enclave_type_t type,
      uint32_t flags,
      const oe_enclave_setting_t* settings,
      uint32_t setting_count,
      oe_enclave_t** enclave)
    {
        return oe_create_enclave(
                 path,
                 type,
                 flags,
                 settings,
                 setting_count,
                 __foo_ocall_function_table,
                 3,
                 __foo_ecall_info_table,
                 3,
                 enclave);
    }
    ```
  - During the initialization of the local table, the host uses the following logic
    to get the global id by name.
    ```
    uint32_t i, index;
    for (i = 0; i < ecall_info_table_size; i++)
    {
      if found name in the global_table
        index = the index of the name
      else /* not found */
        add the name to the table
        index = the index of the name

      /* Assign the ECALL id to the local table based on the global id. */
      enclave->ecall_id_table[index] = i;
    }
    ```
  - Modify the internal `oe_call_enclave_function` function to pass a global id
    and the name string of the ECALL instead of hard-coded ECALL id.
    The `global_id` is defined as a *static variable*. Given the same `global_id`
    is used to retrieve the same ECALL across enclaves, the host initializes the
    `global_id` (based on the name) in the first invocation and uses the cached value
    for the subsequent ones.
    ```
    static uint64_t global_id = OE_GLOBAL_ECALL_ID_NULL;
    ...
    /* Call enclave function. */
    if ((_result = oe_call_enclave_function(
             enclave,
             &global_id,
             __foo_ecall_info_table[foo_fcn_id_ecall_common_1_ecall],
             _input_buffer,
             _input_buffer_size,
             _output_buffer,
             _output_buffer_size,
             &_output_bytes_written)) != OE_OK)
      goto done;
    ```

In our previous example, assuming that the host instantiates the `foo` before `bar`.
By applying the above scheme, the host will maintain the following data structures.
- `_ecall_table`
  ```
  _ecall_table[0]: { "ecall_common_1_ecall" }
  _ecall_table[1]: { "ecall_common_2_ecall_1" }
  _ecall_table[2]: { "ecall_common_2_ecall_2" }
  _ecall_table[3]: { "ecall_foo_ecall" }
  _ecall_table[4]: { "ecall_bar_ecall" }
  ```
- `foo` (at the time `bar` is not initialized yet)
  ```
  enclave->ecall_id_table[0]: { 0 /* ecall_common_1_ecall */ }
  enclave->ecall_id_table[1]: { 1 /* ecall_common_2_ecall_1 */ }
  enclave->ecall_id_table[2]: { 2 /* ecall_common_2_ecall_2 */ }
  enclave->ecall_id_table[3]: { 3 /* ecall_foo_ecall */ }
  ```
- `bar`
  ```
  enclave->ecall_id_table[0]: { 2 /* ecall_common_1_ecall */ }
  enclave->ecall_id_table[1]: { 0 /* ecall_common_2_ecall_1 */ }
  enclave->ecall_id_table[2]: { 1 /* ecall_common_2_ecall_2 */ }
  enclave->ecall_id_table[3]: { OE_ECALL_ID_NULL /* ecall_foo_ecall */ }
  enclave->ecall_id_table[4]: { 3 /* ecall_bar_ecall */ }
  ```

In the oeedger8r-generated stub code of `ecall_common_1_ecall`, the local static variable
`global_id` is initialized as `OE_GLOBAL_ECALL_ID_NULL`. After the first invocation of the ecall,
the host looks up the global id by name and sets the `global_id` to `0`. For the subsequent invocations,
the host directly uses the cached value `0` to look up the ecall id from the local table of each enclave
(i.e., getting `0` from `foo` and `2` from `bar`) and therefore achieves the goal of constant-time look-up.

Authors
-------

- Ming-Wei Shih <mishih@microsoft.com>
