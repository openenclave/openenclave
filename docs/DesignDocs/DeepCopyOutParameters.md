Support Deep Copy of Variable-Length Out Parameters
=====

This document provides a brief overview of the oeedger8r's deep copy feature and points out
its missing piece: the support of the deep-copy `out` parameter. Next, the document describes a
design that supports the deep-copy `out` parameter.

Introduction
------------

The oeedger8r tool supports the feature of deep copy, which allows a user to pass a struct with nested pointers
in ECALLs and OCALLs. To leverage this feature, the user should define the struct as part of an EDL file
and use proper annotations on both the struct and the ECALL/OCALL, which intends to pass the struct.
See also [Enforcing full serialization in EDL](/docs/DesignDocs/full_edl_serialization.md).

An example of struct definitions is as follows.

```
struct Blob
{
  size_t len;
  [size=len] char* buf;
};

struct NestedBlob
{
  size_t num;
  [count=num] Blob* blob_array;
};
```

The `num` variable specified to the `count` attribute represents the length (i.e., the number of elements)
of the `blob_array`. Similarly, the `len` variable specified to the `size` attribute represents the size (in bytes) of the `buf`.
Refer to the [Grammar documentation](https://github.com/openenclave/oeedger8r-cpp/blob/master/docs/Grammar.md) for
more information regarding the syntax of oeedger8r.

To pass the `NestedBlob` struct in an ECALL/OCALL, oeedger8r currently supports the following two cases:
- deep-copy `in` parameter
  ```
  // EDL definition
  void foo([in, count=1] NestedBlob *nb);
  ```

  The above code snippet shows an example of passing `nb` as an `in` parameter. In this case,
  the caller is responsible for initializing `nb`, including `nb->num`, the memory pointed by `nb->blob_array`,
  and each element of the array. The callee can then read the nested content of `nb`. However,
  any callee's modifications to `nb` will not reflect on the caller site (i.e., `nb` is effectively read-only to the callee).

- deep-copy `inout` parameter
  ```
  // EDL definition
  void foo([in, out, count=1] NestedBlob *nb);
  ```

  The above definition is an example of passing `nb` as an `inout` parameter. Similar to the case
  of the `in` parameter, the caller is responsible for initializing `nb` and the callee can read
  the nested content of the `nb`. Besides, callee's modifications to `nb` will now reflect on the caller
  site with a limitation that the callee cannot re-allocate or resize `nb->blob_array` and each `buf`
  in the nested element (which could lead to undefined behaviors).

The case that remains unsupported is the deep-copy `out` parameter as shown in the following example.
```
// EDL definition
void foo([out, count=1] NestedBlob *nb);
```
The major difference between the `out` parameter and the other two is that the caller is no longer responsible
for initializing `nb`.
Instead, the callee takes charge of initializing `nb`, which implies that `b->blob_array` and each of the nested
`buf` are variable-length. Such support is required by typical scenarios in which the caller cannot determine the size of
nested buffers in a struct. Note that the caller is still responsible for allocating the `nb` itself. Please refer to the code snippet
in the following section for an example.

Proposed Design
-----------

This document proposes to add the support of deep-copy `out` parameter to OE SDK.

### User Experience

The following code snippet serves as an example that the proposal aims to support.

- Caller
  
  The caller, either an enclave or a host, is required to prepare an instance of `NestedBlob`.
  In this example, `nb` is the instance of `NestedBlob`. The caller then passes `nb` to
  `foo` (OCALL or ECALL). After the execution resumes from `foo`, the caller should expect that `nb`
  has been initialized by the callee.
  Note that the caller should not initialize the content of `nb` before invoking `foo`. Any content
  set before the invocation will not be passed to the callee (i.e., by the definition of an `out`
  parameter) and the content will be overwritten after a successful invocation.

  ```
  NestedBlob nb;
  memset(&nb, 0, sizeof(NestedBlob));
  // nb.num and nb.blob_array have not been initialized yet.
  foo(enclave, &nb); // The case of an ECALL,
                     // or simply foo(&nb) for the case of an OCALL.
  ...
  /* Caller is responsible for freeing the buffers after use. */
  if (nb.blob_array)
  {
      for (size_t i = 0; i < nb.num; i++)
          free(nb.blob_array[i].buf);
      free(nb.blob_array);
  }
  ```

  - Memory management
  
    The caller is responsible for managing the content of `nb` after invoking `foo`.
    Each nested buffer of `nb` is allocated separately and is therefore required to
    releas each of the buffers via `free` as shown in the example.

- Callee

  The callee is responsible for initializing the `nb` if the `nb` is not `NULL`.
  The `nb` being `NULL` indicates that the caller passes `NULL` to `foo`.
  
  ```
  // User-defined code
  void foo(NestedBlob *nb)
  {
      if (!nb)
          return;
      nb->num = 5;
      nb->blob_array = (Blob*)malloc(5 * sizeof(Blob));
      for (size_t i = 0; i < 5; i++)
      {
          Blob* b = &ptr->blob_array[i];
          b->len = 10;
          b->buf = (char*)malloc(10);
          memset(b->buf, 'A', 10);
      }
  }
  ```

  - Memory management

    The callee should **allocate each nested buffer separately on the heap via `malloc` ** as shown in the example.
    These allocated buffers are freed automatically by the oeedger8r-generated code and therefore the
    callee does not need to take further actions. 
    
Note that the proposal does not affect the behavior of the existing deep-copy `inout` parameter.

### Design

The idea of the design is that after the callee (either a host or an enclave) initializes `nb`,
oeedger8r-generated code serializes the content of `nb` into a local buffer. Next, the content of the buffer
is copied over to a caller's buffer. How the buffer is transmitted is TEE-specific;
in the case of SGX in which the enclave has access to the memory on the host, the enclave, either
being the caller or callee, is always responsible for copying the buffer.
Finally, the caller unserializes the received content, which fills up the `nb`.
The rest of the section walks through modified oeedger8r-generated code for both ECALL and OCALL that realizes the design.

Note that this design is compatible with the switchless call feature, which also requires shared memory.

- ECALL

  The design adds `deepcopy_out_buffer` and `deepcopy_out_buffer_size` members to every internal struct of ECALLs.
  The two members are used to hold and to obtain the enclave-set content by the enclave and the host, correspondingly.
  How the content is transmitted across the boundary is TEE-specific, depending on the availability of the shared memory
  between the host and the enclave. The values (zero or not) of the two members are also used by the
  infrastructure to determine whether to transmit the buffer or not.
  
  ```diff
  typedef struct _foo_args_t
  {
      oe_result_t _result;
  +   uint8_t* deepcopy_out_buffer;
  +   size_t deepcopy_out_buffer_size;
      NestedBlob* ptr;
  } foo_args_t;
  ```
  - Host

    Similar to a normal ECALL, the host prepares parameters and invokes `oe_call_enclave_function`.
    After returning from `oe_call_enclave_function`, the host obtains `_deepcopy_out_buffer` and
    `_deepcopy_out_buffer_size` from `pargs_out`. `_deepcopy_out_buffer` holds a local copy of the enclave-set content.
    Next, the host uses the `OE_SET_DEEPCOPY_OUT_PARAM` macro to unserialize the enclave-set content. After unserializing,
    the host validates the `_deepcopy_out_buffer_offset` (increased during unserialization) against `_deepcopy_out_buffer_size`.
    Before finishing the function, the host frees `_deepcopy_out_buffer`.
    
The following is an example of oeedger8r-generated code:
    ```diff
    oe_result_t foo(
        oe_enclave_t* enclave,
        NestedBlob* ptr)
    {
        oe_result_t _result = OE_FAILURE;

        static uint64_t global_id = OE_GLOBAL_ECALL_ID_NULL;

        /* Marshalling struct. */
        foo_args_t _args, *_pargs_in = NULL, *_pargs_out = NULL;
        /* Marshalling buffer and sizes. */
        size_t _input_buffer_size = 0;
        size_t _output_buffer_size = 0;
        size_t _total_buffer_size = 0;
        uint8_t* _buffer = NULL;
        uint8_t* _input_buffer = NULL;
        uint8_t* _output_buffer = NULL;
        size_t _input_buffer_offset = 0;
        size_t _output_buffer_offset = 0;
        size_t _output_bytes_written = 0;
    +   uint8_t* _deepcopy_out_buffer = NULL;
    +   size_t _deepcopy_out_buffer_size = 0;
    +   size_t _deepcopy_out_buffer_offset = 0;

       /* Fill marshalling struct. */
        memset(&_args, 0, sizeof(_args));
        _args.ptr = (NestedBlob*)ptr;

        /* Compute input buffer size. Include in and in-out parameters. */
        OE_ADD_SIZE(_input_buffer_size, sizeof(foo_args_t));
        /* There were no corresponding parameters. */
    
        /* Compute output buffer size. Include out and in-out parameters. */
        OE_ADD_SIZE(_output_buffer_size, sizeof(foo_args_t));
        if (ptr)
            OE_ADD_SIZE(_output_buffer_size, ((size_t)1 * sizeof(NestedBlob)));
    
        /* Allocate marshalling buffer. */
        _total_buffer_size = _input_buffer_size;
        OE_ADD_SIZE(_total_buffer_size, _output_buffer_size);
        _buffer = (uint8_t*)oe_malloc(_total_buffer_size);
        _input_buffer = _buffer;
        _output_buffer = _buffer + _input_buffer_size;
        if (_buffer == NULL)
        {
            _result = OE_OUT_OF_MEMORY;
            goto done;
        }
    
        /* Serialize buffer inputs (in and in-out parameters). */
        _pargs_in = (enc_foo_args_t*)_input_buffer;
        OE_ADD_SIZE(_input_buffer_offset, sizeof(*_pargs_in));
        /* There were no in nor in-out parameters. */
    
        /* Copy args structure (now filled) to input buffer. */
        memcpy(_pargs_in, &_args, sizeof(*_pargs_in));

        /* Call enclave function. */
        if ((_result = oe_call_enclave_function(
                 enclave,
                 &global_id,
                 __test_ecall_info_table[test_fcn_id_enc_foo].name,
                 _input_buffer,
                 _input_buffer_size,
                 _output_buffer,
                 _output_buffer_size,
                 &_output_bytes_written)) != OE_OK)
            goto done;

        /* Setup output arg struct pointer. */
        _pargs_out = (foo_args_t*)_output_buffer;
        OE_ADD_SIZE(_output_buffer_offset, sizeof(*_pargs_out));
    
        /* Check if the call succeeded. */
        if ((_result = _pargs_out->_result) != OE_OK)
            goto done;

        /* Currently exactly _output_buffer_size bytes must be written. */
        if (_output_bytes_written != _output_buffer_size)
        {
            _result = OE_FAILURE;
            goto done;
        }

    +   _deepcopy_out_buffer = _pargs_out->deepcopy_out_buffer;
    +   _deepcopy_out_buffer_size = _pargs_out->deepcopy_out_buffer_size;

        /* Unmarshal return value and out, in-out parameters. */
        /* No return value. */

    +   OE_READ_OUT_PARAM(ptr, (size_t)(((size_t)1 * sizeof(NestedBlob))));
    +   if (ptr && ptr->blob_array)
    +       OE_SET_DEEPCOPY_OUT_PARAM(ptr->blob_array, ((size_t)ptr->num * sizeof(Blob)), Blob*);
    +   for (size_t _i_2 = 0; _i_2 < ptr->num; _i_2++)
    +   {
    +       if (ptr && ptr->blob_array && ptr->blob_array[_i_2].buf)
    +           OE_SET_DEEPCOPY_OUT_PARAM(ptr->blob_array[_i_2].buf, ptr->blob_array[_i_2].len, char*);
    +   }

    +   if (_deepcopy_out_buffer_offset != _deepcopy_out_buffer_size)
    +   {
    +       _result = OE_FAILURE;
    +       goto done;
    +   }

        _result = OE_OK;

    done:
        if (_buffer)
            oe_free(_buffer);

    +   if (_deepcopy_out_buffer)
    +       oe_free(_deepcopy_out_buffer);

        return _result;
    }
    ```

  - Enclave

    Upon the dispatching of the ECALL, the oeedger8r-generated
    `ecall_foo` is invoked as usual. After the invocation of
    the user-defined `foo` function, the enclave calculates the size
    of content set by `foo`. Next, the enclave allocates an in-enclave
    buffer, `_deepcopy_out_buffer`, and serializes the content into the buffer using the
    `OE_WRITE_DEEPCOPY_OUT_PARAM` macro.
    After serializing, the enclave allocates sets the `_deepcopy_out_buffer` and `_deepcopy_out_buffer_size`
    to `pargs_out`. After the execution of the `ecall_foo`, the infrasturce will determine how
    to transmit the buffer over to the host.
    Before terminating the function, the enclave releases the content set by `foo`.
    Therefore, only the host is responsible for managing the memory of `nb` set by the ECALL `foo`.

    ```diff
    static void ecall_foo(
        uint8_t* input_buffer,
        size_t input_buffer_size,
        uint8_t* output_buffer,
        size_t output_buffer_size,
        size_t* output_bytes_written)
    {
        oe_result_t _result = OE_FAILURE;

        /* Prepare parameters. */
        foo_args_t* pargs_in = (foo_args_t*)input_buffer;
        foo_args_t* pargs_out = (foo_args_t*)output_buffer;

    +   uint8_t* _deepcopy_out_buffer = NULL;
    +   size_t _deepcopy_out_buffer_offset = 0;
    +   size_t _deepcopy_out_buffer_size = 0;

        size_t input_buffer_offset = 0;
        size_t output_buffer_offset = 0;
        OE_ADD_SIZE(input_buffer_offset, sizeof(*pargs_in));
        OE_ADD_SIZE(output_buffer_offset, sizeof(*pargs_out));

        /* Make sure input and output buffers lie within the enclave. */
        /* oe_is_within_enclave explicitly checks if buffers are null or not. */
        if (!oe_is_within_enclave(input_buffer, input_buffer_size))
            goto done;

        if (!oe_is_within_enclave(output_buffer, output_buffer_size))
            goto done;

        /* Set in and in-out pointers. */
        /* There were no in nor in-out parameters. */

        /* Set out and in-out pointers. */
        /* In-out parameters are copied to output buffer. */
        if (pargs_in->ptr)
            OE_SET_OUT_POINTER(ptr, ((size_t)1 * sizeof(NestedBlob)), NestedBlob*);

        /* Check that in/in-out strings are null terminated. */
        /* There were no in nor in-out string parameters. */

        /* lfence after checks. */
        oe_lfence();

        /* Call user function. */
        foo(
            pargs_in->ptr);

    +   /* Compute the size for the deep-copy out buffer. */
    +   if (pargs_in->ptr && pargs_in->ptr->blob_array)
    +       OE_ADD_SIZE(_deepcopy_out_buffer_size, ((size_t)pargs_in->ptr->num * sizeof(Blob)));
    +   for (size_t _i_2 = 0; _i_2 < pargs_in->ptr->num; _i_2++)
    +   {
    +       if (pargs_in->ptr && pargs_in->ptr->blob_array && pargs_in->ptr->blob_array[_i_2].buf)
    +       OE_ADD_SIZE(_deepcopy_out_buffer_size, pargs_in->ptr->blob_array[_i_2].len);
    +   }

    +   if (_deepcopy_out_buffer_size)
    +   {
    +       _deepcopy_out_buffer = (uint8_t*) oe_malloc(_deepcopy_out_buffer_size);
    +       if (!_deepcopy_out_buffer)
    +       {
    +           _result = OE_OUT_OF_MEMORY;
    +           goto done;
    +       }
    +   }

    +   /* Serialize the deep-copied content into the buffer. */
    +   if (pargs_in->ptr && pargs_in->ptr[_i_1].blob_array)
    +       OE_WRITE_DEEPCOPY_OUT_PARAM(pargs_in->ptr[_i_1].blob_array, ((size_t)pargs_in->ptr[_i_1].num * sizeof(Blob)));
    +   for (size_t _i_2 = 0; _i_2 < pargs_in->ptr[_i_1].num; _i_2++)
    +   {
    +       if (pargs_in->ptr && pargs_in->ptr[_i_1].blob_array && pargs_in->ptr[_i_1].blob_array[_i_2].buf)
    +           OE_WRITE_DEEPCOPY_OUT_PARAM(pargs_in->ptr[_i_1].blob_array[_i_2].buf, pargs_in->ptr[_i_1].blob_array[_i_2].len);
    +   }

    +   if (_deepcopy_out_buffer_offset != _deepcopy_out_buffer_size)
    +   {
    +       _result = OE_FAILURE;
    +       goto done;
    +   }
    +   OE_ADD_SIZE(output_buffer_offset, _deepcopy_out_buffer_size);

    +   /* Set the _deepcopy_out_buffer and _deepcopy_out_buffer as part of pargs_out. */
    +   pargs_out->deepcopy_out_buffer = _deepcopy_out_buffer;
    +   pargs_out->deepcopy_out_buffer_size = _deepcopy_out_buffer_size;

        /* Success. */
        _result = OE_OK;
        *output_bytes_written = output_buffer_offset;

    done:
    +   /* Free pargs_out->deepcopy_out_buffer on failure. */
    +   if (_result != OE_OK)
    +   {
    +       oe_free(pargs_out->deepcopy_out_buffer);
    +       pargs_out->deepcopy_out_buffer = NULL;
    +       pargs_out->deepcopy_out_buffer_size = 0;
    +   }

    +   /* Free nested buffers allocated by the user function. */
    +   if (pargs_in->ptr)
    +   {
    +       for (size_t _i_1 = 0; _i_1 < 1; _i_1++)
    +       {
    +           if (pargs_in->ptr[_i_1].blob_array)
    +           {
    +               for (size_t _i_2 = 0; _i_2 < pargs_in->ptr[_i_1].num; _i_2++)
    +               {
    +                   free(pargs_in->ptr[_i_1].blob_array[_i_2].buf);
    +               }
    +           }
    +           free(pargs_in->ptr[_i_1].blob_array);
    +       }
    +   }

        if (output_buffer_size >= sizeof(*pargs_out) &&
            oe_is_within_enclave(pargs_out, output_buffer_size))
            pargs_out->_result = _result;
    }
    ```

- OCALL

  Similar to the case of ECALL, the design adds the same modifications to every internal struct of OCALLs.
  ```diff
  typedef struct _foo_args_t
  {
      oe_result_t _result;
  +   uint8_t* deepcopy_out_buffer;
  +   size_t deepcopy_out_buffer_size;
      NestedBlob* ptr;
  } foo_args_t;
  ```

  - Enclave

    The modified code is similar to the case of an ECALL. The difference is that
    the enclave performs an additional check against the `_deepcopy_out_buffer` to ensure
    that the buffer stays within the enclave memory.

    ```diff
    oe_result_t foo(NestedBlob* ptr)
    {
        oe_result_t _result = OE_FAILURE;

        /* If the enclave is in crashing/crashed status, new OCALL should fail
           immediately. */
        if (oe_get_enclave_status() != OE_OK)
            return oe_get_enclave_status();

        /* Marshalling struct. */
        foo_args_t _args, *_pargs_in = NULL, *_pargs_out = NULL;
        /* Marshalling buffer and sizes. */
        size_t _input_buffer_size = 0;
        size_t _output_buffer_size = 0;
        size_t _total_buffer_size = 0;
        uint8_t* _buffer = NULL;
        uint8_t* _input_buffer = NULL;
        uint8_t* _output_buffer = NULL;
        size_t _input_buffer_offset = 0;
        size_t _output_buffer_offset = 0;
        size_t _output_bytes_written = 0;
    +   uint8_t* _deepcopy_out_buffer = NULL;
    +   size_t _deepcopy_out_buffer_size = 0;
    +   size_t _deepcopy_out_buffer_offset = 0;

        /* Fill marshalling struct. */
        memset(&_args, 0, sizeof(_args));
        _args.ptr = (NestedBlob*)ptr;

        /* Compute input buffer size. Include in and in-out parameters. */
        OE_ADD_SIZE(_input_buffer_size, sizeof(foo_args_t));
        /* There were no corresponding parameters. */
    
        /* Compute output buffer size. Include out and in-out parameters. */
        OE_ADD_SIZE(_output_buffer_size, sizeof(foo_args_t));
        if (ptr)
            OE_ADD_SIZE(_output_buffer_size, ((size_t)1 * sizeof(NestedBlob)));
    
        /* Allocate marshalling buffer. */
        _total_buffer_size = _input_buffer_size;
        OE_ADD_SIZE(_total_buffer_size, _output_buffer_size);
        _buffer = (uint8_t*)oe_allocate_ocall_buffer(_total_buffer_size);
        _input_buffer = _buffer;
        _output_buffer = _buffer + _input_buffer_size;
        if (_buffer == NULL)
        {
            _result = OE_OUT_OF_MEMORY;
            goto done;
        }
    
        /* Serialize buffer inputs (in and in-out parameters). */
        _pargs_in = (foo_args_t*)_input_buffer;
        OE_ADD_SIZE(_input_buffer_offset, sizeof(*_pargs_in));
        /* There were no in nor in-out parameters. */
    
        /* Copy args structure (now filled) to input buffer. */
        memcpy(_pargs_in, &_args, sizeof(*_pargs_in));

        /* Call host function. */
        if ((_result = oe_call_host_function(
                 test_fcn_id_foo,
                 _input_buffer,
                 _input_buffer_size,
                 _output_buffer,
                 _output_buffer_size,
                 &_output_bytes_written)) != OE_OK)
            goto done;

        /* Setup output arg struct pointer. */
        _pargs_out = (foo_args_t*)_output_buffer;
        OE_ADD_SIZE(_output_buffer_offset, sizeof(*_pargs_out));
    
        /* Check if the call succeeded. */
        if ((_result = _pargs_out->_result) != OE_OK)
            goto done;

        /* Currently exactly _output_buffer_size bytes must be written. */
        if (_output_bytes_written != _output_buffer_size)
        {
            _result = OE_FAILURE;
            goto done;
        }

    +    _deepcopy_out_buffer = _pargs_out->deepcopy_out_buffer;
    +    _deepcopy_out_buffer_size = _pargs_out->deepcopy_out_buffer_size;
    +    if (_deepcopy_out_buffer && _deepcopy_out_buffer_size && 
    +        !oe_is_within_enclave(_deepcopy_out_buffer, _deepcopy_out_buffer_size))
    +    {
    +        _result = OE_FAILURE;
    +        goto done;
    +    }

        /* Unmarshal return value and out, in-out parameters. */
        /* No return value. */

    +   OE_READ_OUT_PARAM(ptr, (size_t)(((size_t)1 * sizeof(NestedBlob))));
    +   if (ptr && ptr->blob_array)
    +       OE_SET_DEEPCOPY_OUT_PARAM(ptr->blob_array, ((size_t)ptr->num * sizeof(Blob)), Blob*);
    +   for (size_t _i_2 = 0; _i_2 < ptr->num; _i_2++)
    +   {
    +       if (ptr && ptr->blob_array && ptr->blob_array[_i_2].buf)
    +           OE_SET_DEEPCOPY_OUT_PARAM(ptr->blob_array[_i_2].buf, ptr->blob_array[_i_2].len, char*);
    +   }

    +   if (_deepcopy_out_buffer_offset != _deepcopy_out_buffer_size)
    +   {
    +       _result = OE_FAILURE;
    +       goto done;
    +   }

        /* Retrieve propagated errno from OCALL. */
        /* Errno propagation not enabled. */

        _result = OE_OK;

    done:
        if (_buffer)
            oe_free_ocall_buffer(_buffer);

    +   if (_deepcopy_out_buffer)
    +       oe_free(_deepcopy_out_buffer);

        return _result;
    }
    ```

  - Host

    The modified code is similar to the case of an ECALL.
    ```diff
    static void ocall_foo(
        uint8_t* input_buffer,
        size_t input_buffer_size,
        uint8_t* output_buffer,
        size_t output_buffer_size,
        size_t* output_bytes_written)
    {
        oe_result_t _result = OE_FAILURE;
        OE_UNUSED(input_buffer_size);

        /* Prepare parameters. */
        foo_args_t* pargs_in = (foo_args_t*)input_buffer;
        foo_args_t* pargs_out = (foo_args_t*)output_buffer;

    +   uint8_t* _deepcopy_out_buffer = NULL;
    +   size_t _deepcopy_out_buffer_offset = 0;
    +   size_t _deepcopy_out_buffer_size = 0;

        size_t input_buffer_offset = 0;
        size_t output_buffer_offset = 0;
        OE_ADD_SIZE(input_buffer_offset, sizeof(*pargs_in));
        OE_ADD_SIZE(output_buffer_offset, sizeof(*pargs_out));

        /* Make sure input and output buffers are valid. */
        if (!input_buffer || !output_buffer) {
            _result = OE_INVALID_PARAMETER;
            goto done;
        }

        /* Set in and in-out pointers. */
        /* There were no in nor in-out parameters. */

        /* Set out and in-out pointers. */
        /* In-out parameters are copied to output buffer. */
        if (pargs_in->ptr)
            OE_SET_OUT_POINTER(ptr, ((size_t)1 * sizeof(NestedBlob)), NestedBlob*);

        /* Call user function. */
        foo(
            pargs_in->ptr);

    +   /* Compute the size for the deep-copy out buffer. */
    +   if (pargs_in->ptr && pargs_in->ptr->blob_array)
    +       OE_ADD_SIZE(_deepcopy_out_buffer_size, ((size_t)pargs_in->ptr->num * sizeof(Blob)));
    +   for (size_t _i_2 = 0; _i_2 < pargs_in->ptr->num; _i_2++)
    +   {
    +       if (pargs_in->ptr && pargs_in->ptr->blob_array && pargs_in->ptr->blob_array[_i_2].buf)
    +           OE_ADD_SIZE(_deepcopy_out_buffer_size, pargs_in->ptr->blob_array[_i_2].len);
    +   }

    +   if (_deepcopy_out_buffer_size)
    +   {
    +       _deepcopy_out_buffer = (uint8_t*) oe_malloc(_deepcopy_out_buffer_size);
    +       if (!_deepcopy_out_buffer)
    +       {
    +           _result = OE_OUT_OF_MEMORY;
    +           goto done;
    +       }
    +   }

    +   /* Serialize the deep-copied content into the buffer. */
    +   if (pargs_in->ptr && pargs_in->ptr->blob_array)
    +       OE_WRITE_DEEPCOPY_OUT_PARAM(pargs_in->ptr->blob_array, ((size_t)pargs_in->ptr->num * sizeof(Blob)));
    +   for (size_t _i_2 = 0; _i_2 < pargs_in->ptr->num; _i_2++)
    +   {
    +       if (pargs_in->ptr && pargs_in->ptr->blob_array && pargs_in->ptr->blob_array[_i_2].buf)
    +           OE_WRITE_DEEPCOPY_OUT_PARAM(pargs_in->ptr->blob_array[_i_2].buf, pargs_in->ptr->blob_array[_i_2].len);
    +   }

    +   if (_deepcopy_out_buffer_offset != _deepcopy_out_buffer_size)
    +   {
    +       _result = OE_FAILURE;
    +       goto done;
    +   }
    +   OE_ADD_SIZE(output_buffer_offset, _deepcopy_out_buffer_size);

    +   /* Set the _deepcopy_out_buffer and _deepcopy_out_buffer as part of pargs_out. */
    +   pargs_out->deepcopy_out_buffer = _deepcopy_out_buffer;
    +   pargs_out->deepcopy_out_buffer_size = _deepcopy_out_buffer_size;

        /* Propagate errno back to enclave. */
        /* Errno propagation not enabled. */

        /* Success. */
        _result = OE_OK;
        *output_bytes_written = output_buffer_offset;

    done:
    +   /* Free pargs_out->deepcopy_out_buffer on failure. */
    +   if (_result != OE_OK)
    +   {
    +       free(pargs_out->deepcopy_out_buffer);
    +       pargs_out->deepcopy_out_buffer = NULL;
    +       pargs_out->deepcopy_out_buffer_size = 0;
    +   }

    +   /* Free nested buffers allocated by the host. */
    +   if (pargs_in->ptr)
    +   {
    +       for (size_t _i_1 = 0; _i_1 < 1; _i_1++)
    +       {
    +           if (pargs_in->ptr[_i_1].blob_array)
    +           {
    +               for (size_t _i_2 = 0; _i_2 < pargs_in->ptr[_i_1].num; _i_2++)
    +               {
    +                   free(pargs_in->ptr[_i_1].blob_array[_i_2].buf);
    +                   pargs_in->ptr[_i_1].blob_array[_i_2].buf = NULL;
    +               }
    +           }
    +           free(pargs_in->ptr[_i_1].blob_array);
    +           pargs_in->ptr[_i_1].blob_array = NULL;
    +       }
    +   }

        if (pargs_out && output_buffer_size >= sizeof(*pargs_out))
            pargs_out->_result = _result;
    }
    ```

Conclusion and Plan
-----------

This document presents the design, which supports deep-copy `out` parameter.
Moving forward, we plan to support the design as an experimental feature first.
That is, users need to explicitly opt-in the feature (i.e., specifying `--experimental` flag in the
command line when invoking the oeedger8r tool). Doing so allows OE to support the deep-copy `out` parameter
in SGX while not introducing breaking changes to the OE's support on OP-TEE.

Authors
-------

- Ming-Wei Shih <mishih@microsoft.com>
