# Security Guidance for Intel Processor MMIO Stale Data Vulnerabilities

## Introduction

A partial write (smaller than 8 byte or non-8-byte aligned) to the host memory from
an enclave allows the malicious host to use the vulnerability to read enclave data
(i.e., the previous stale data inside CPU buffers). Note that the vulnerabilities
are introduced by hardwares bugs rather than bugs in software or OE SDK.

To protect enclave applications against the vulnerabilities, users need to adopt the
OE SDK version greater or equal to `v0.18.0` and re-compile their applications (including
re-generating edge routines via oeedger8r). In addition, users may need to manually
patch their source code if it includes vulnerable code patterns that bypass OE SDK’s
protection.

## Vulnerable Area

Writes to host memory usually occur during the ECALL (for returning out, in/out
parameters and return value) and OCALL (for passing in and in/out parameters). The OE
updates have safeguarded such surface. The patch involves changes to OE libraries
(hardening internal host memory writes) and the oeedger8r tool (generating secure
marshalling code). However, certain usages of oeedger8r could generate ECALL or OCALL
marshalling code that bypasses OE’s protection. In such cases, the host pointers may be
passed to the enclave, and the enclave could directly writes to host memory via those
pointers, resulting in potentially vulnerable code patterns (see the examples below).

```c
/*
 * Enclave code
 * host_memory_ptr is passed in to the enclave that points to the host memory
 */

/* Example: non-8-byte-aligned host memory write */
memcpy(host_memory_ptr, context, 16); // @host_memory_ptr = 0x1002

/* Example: non-8-byte-aligned host memory write on trailing bytes */
memcpy(host_memory_ptr, content, 20); // @host_memory_ptr = 0x1000

/* Example: writes to host struct */
host_struct->member = 5;
```

Examples of oeedger8r protection bypassing:
1. Use of user_check pointers

   The application may pass host pointers via `user_check` parameters in ECALLs, which
   effectively bypass the OE’s protection. Any write to such pointers requires manual
   patching to enforce the mitigation. An example of the vulnerable ECALL declaration
   is as follows.

   ```c
   // ECALL
   trusted {
       // Pass the host pointer with the user_check annotation
       public void ecall_test([user_check] void* host_ptr);
    };
   ```

2. Pass host memory address in value

   Similar to the use of `user_check` pointer, the application may pass host pointers via
   a 64-bit value type parameter (e.g., `uint64_t`) in ECALLs, the return value in OCALLs,
   or a of struct member in ECALLs and OCALLs. Any write to such pointers (via casting the
   value) requires manual patching to enforce the mitigation. Examples of vulnerable
   ECALL and OCALL declarations are as follows.


   ```c
   struct test_struct {
       uint64_t host_ptr;
   };

   // ECALLs
   trusted {
       // Pass the host pointer in value
       public void ecall_test(uint64_t host_ptr);

       // Pass the host pointer in value as the struct member
       public void ecall_test_struct_1(test_struct host_struct);

       // Pass the host pointer in value as the struct member
       public void ecall_test_struct_2([in] test_struct* host_struct_ptr);

       // Pass the host pointer in value as the struct member
       public void ecall_test_struct_3([in, out] test_struct* host_struct_ptr);
   };

   // OCALLs
   untrusted {
       // Pass the host pointer as the return value
       uint64_t ocall_get_host_ptr();

       // Pass the host pointer as the struct member
       void ocall_get_test_struct_1([out] test_struct* host_struct_ptr);

       // Pass the host pointer as the struct member
       void ocall_get_test_struct_2([in, out] test_struct* host_struct_ptr);
   };
   ```

3. Allocate host memory inside the enclave

   Another vulnerable case is dynamically allocating memory from host heap (e.g., via
   `oe_host_malloc` or a customized OCALL that invokes `malloc` on the host) and writing
   to the memory. Such writes also require manual patching to enforce the mitigation.

   A common pattern of such cases is passing a double pointer in an ECALL and expecting
   the ECALL to return a variable-length out buffer (which lies in the host memory such
   that the host can access). See an example below.

   ```c
   // ECALL
   trusted {
        // Pass a double pointer and expect the enclave to allocate and return host buffer
        public void ecall_test([out] uint8_t **buffer, [out] size_t* size);
   };

   // ECALL implementation (simplified version)
   void ecall_test(uint8_t **buffer, size_t* size)
   {
       // Allocate host buffer
       *buffer = oe_host_malloc(enclave_buffer_size);

       // Potentially vulnerable memory write to the host
       memcpy(*buffer, enclave_buffer, enclave_buffer_size);

       *size = enclave_buffer_size;
   }
   ```

## Mitigation

To help users mitigate the above-mentioned cases, this section presents guidelines to
patch the code.

1. Replacing double pointers with deep-copy feature in the EDL

   ```c
   // After patching

   // Annotated struct
   struct buffer_t
   {
       [size=size] uint8_t* data;
       size_t size;
   };

   trusted {
       // Use out pointer of the annotated buffer_t
       public void ecall([out] buffer_t* output_buffer);
   };

   // ECALL implementation (simplified version)
   void ecall_test(buffer_t* output_buffer)
   {
       // Allocate an enclave buffer
       output_buffer->data = malloc(enclave_buffer_size);

       // No more host writes
       memcpy(output_buffer->data, enclave_buffer, enclave_buffer_size);

       output_buffer->size = enclave_buffer_size;
   }
   ```

2. Patching `memcpy`, `memmove`, and `memset` with harndend APIs

   One approach to mitigate writes to host memory via these libc APIs
   is validating the address of the memory and the number of bytes
   to be written before the invocation.

   ```c
   // Before patching

   // Potentially vulnerable writes to the host memory via memcpy
   memcpy(host_ptr_1, enclave_ptr, size_1);

   // After patching
   // NOTE: this code assumes the implementation of memcpy only
   // does 8-byte writes.
   if ((host_ptr_1 % 8 == 0) || (size_1 % 8 == 0))
       memcpy(host_ptr_1, enclave_ptr, size_1); // Only allow safe write
   else
       abort(); // Not safe to write, abort
   ```

   To ease the effort on adding such checks to every host memory writes
   and to allow host memory writes even if the address and size are not
   8-byte aligned, OE provides new APIs that can securely replace these APIs.
   The list of APIs is as follows.

   ```c
   void* oe_memcpy_with_barrier(void* dest, const void* src, size_t count);
   void* oe_memmove_with_barrier(void* dest, const void* src, size_t count);
   void* oe_memset_with_barrier(void* dest, int value, size_t count);

   oe_result_t oe_memcpy_s_with_barrier(
       void* dest, size_t dest_size, const void* src, size_t num_bytes);
   oe_result_t oe_memmove_s_with_barrier(
       void* dest, size_t dest_size, const void* src, size_t num_bytes);
   oe_result_t oe_memset_s_with_barrier(
       void* dest, size_t dest_size, int value, size_t num_bytes);
   ```

   If users want better security, they can use `oe_memcpy_s_with_barrier`,
   `oe_memmove_s_with_barrier` and `oe_memset_s_with_barrier`, which additionally
   validate the input parameters.

   Note that these APIs are only beneficial when the `dest` points to host memory
   otherwise they will only add redundant run-time overhead.

   ```c
   // Before patching

   // Potentially vulnerable writes to the host memory via memcpy and memset
   memcpy(host_ptr_1, enclave_ptr, size_1);
   memmove(host_ptr_2, enclave_ptr, size_2);
   memset(host_ptr_3, 0, size_3);

   // After patching
   oe_memcpy_with_barrier(host_ptr_1, enclave_ptr, size_1);
   oe_memmove_with_barrier(host_ptr_2, enclave_ptr, size_2);
   oe_memset_with_barrier(host_ptr_3, 0, size_3);

   // Alternatives (using secure version of memcpy and memset)
   oe_memcpy_s_with_barrier(host_ptr_1, size_1, enclave_ptr, size_1);
   oe_memmove_s_with_barrier(host_ptr_2, size_2, enclave_ptr, size_2);
   oe_memset_s_with_barrier(host_ptr_3, size_3, 0, size_3);
   ```

3. Patching variable assignment

   The application may write to the host memory through variable assignment. For example,
   assigning value to a struct member where the struct lies in the host memory. In this
   case, users would need to convert the variable assignment based on the newly
   introduced OE_WRITE_VALUE_WITH_BARRIER macro.

   ```c
   // C marco where value requires explicitly type casting if it is constant
   // Only standard C types are allowed (i.g., 1-, 2-, 4-, or 8-bytes)
   OE_WRITE_VALUE_WITH_BARRIER(dest, value)
   ```

   The example usage of the macro is as follows.

   ```c
   // struct declaration
   struct test_struct {
       int a;
       long b;
   };

   // Before patching

   // Potentially vulnerable writes to the host memory through variable assignment
   // (test_struct_pointer points to the host memory);
   test_struct_pointer->a = 10;
   test_struct_pointer->b = 20;

   // After patching
   OE_WRITE_VALUE_WITH_BARRIER(&test_struct_pointer->a, (int)10);
   OE_WRITE_VALUE_WITH_BARRIER(&test_struct_pointer->b, (long)20);
   ```