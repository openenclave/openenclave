# Best practices for keeping enclaves secure
Use this guide to apply secure patterns and avoid common mistakes that put the
security of enclave applications at risk.

1. [Best practices for interface custom marshaling](#1-best-practices-for-interface-custom-marshaling)

    1.1 [Ensuring memory is where it should be](#11-ensuring-memory-is-where-it-should-be)

    1.2 [Memory bounds: oe_is_within_enclave vs. oe_is_outside_enclave](#12-Memory-bounds-oe_is_within_enclave-vs-oe_is_outside_enclave)

    1.3 [TOCTOU or double fetch vulnerabilities](#13-toctou-or-double-fetch-vulnerabilities)

    1.4 [Ensure proper bounding of data buffers](#14-ensure-proper-bounding-of-data-buffers)

    1.5 [Updated enclave ecall with custom marshaling](#15-updated-enclave-ecall-with-custom-marshaling)

2. [Handling secrets in enclave applications](#2-handling-secrets-in-enclave-applications)

    2.1 [How _not_ to handle application secrets](#21-how-not-to-handle-application-secrets)

    2.2 [The new secure enclave way to handle application secrets](#22-the-new-secure-enclave-way-to-handle-application-secrets)

<br />
<br />
<br />

# 1. Best practices for interface custom marshaling 
(For an overview of using the Enclave Definition Language (EDL) and the
oeedger8r tool to produce enclave interface code, please refer to
[Getting started with the Open Enclave edger8r](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/Edger8rGettingStarted.md).)

Calling into and out of enclaves uses special methods that orchestrate the
context switch and marshal the function parameters. Much of the code necessary
to manage these calls and parameter marshaling are common to most applications.
The Open Enclave _oeedger8r_, using the interface definition defined by
application developers in EDL files, generates boilerplate code for them.

In some uncommon cases, developers may want to pass data types that are not
defined at the interface level or handle marshaling differently from what the
oeedger8r tool generates. Although this is not generally recommended, it is
supported. To specify this, use `user_check` for the parameter
constraint like the following example:

```c++
enclave {
    trusted {
        public void ecall_with_user_check(
            [user_check] void* blob);
    };
};
```
In this simplified EDL example, the function takes one pointer-to-void
parameter. Remember that the primary benefit of using supported types in the EDL
is that the generated boilerplate code performs the necessary and secure
marshaling for the developer. When developers specify that a parameter is
`user_check`, they are signaling to oeedger8r that their application code will
perform the marshaling. (Two examples of when custom marshaling is helpful
are 1) when data formats are dynamic, and 2) when sharing large blocks of
memory&mdash;custom marshaling avoids the boilerplate code's intermediate copying of data
into safe enclave buffers.)

> We'd like to stress that a secure best practice for enclave interfaces is to
_avoid_ custom marshaling. But we understand that there may be cases where
avoiding it is impractical, so in these sections we will help developers do it
safely.

The ecall function implementation below has several problems. We will be
correcting this code as we move through the material. The code also assumes that the enclave
can directly read the blob memory, which is true for SGX but may not be true for other TEEs.  The general impetus for
custom marshaling in this sample code is to avoid expensive intermediate copying
of shared memory introduced by the oeedger8r's generated code. (Data passed to
`render_data()` is "flat", that is, the data format is non-referential and thus
non-_self_-referencing. These attributes reduce threats to enclaves from
untrusted data streams. More on this in the following sections.)

```c++
typedef struct _blob {
    void* data;
    size_t size;
} blob_t;

// WARNING: Portions of this code are intentionally flawed to demonstrate common
// pitfalls.
int ecall_with_user_check0(void* ptr) {

    blob_t* blob;

    if (ptr == nullptr)
        return -1;

    blob = (blob_t*)ptr;

    // Blobs to be rendered are limited to 4K.
    if (blob->size > 4096)
        return -1;

    return render_data(blob->data, blob->size);
}
```

## 1.1 Ensuring memory is where it should be

Remember that the code we are focused on is running _inside_ of the enclave.
The caller invoked this ecall function from _outside_ the enclave, passing in a
pointer to memory containing well-formed data (in the non-malicious case).
But in the Open Enclave security model, the ecall invoker is untrusted&mdash;we must
treat untrusted input with caution.

One important security check is to ensure that memory buffers are on the correct
side of the security boundary. The Open Enclave SDK provides two library
functions for checking memory buffers:
`oe_is_within_enclave()` and `oe_is_outside_enclave()`.

Let's update the code to ensure that the memory buffer is at least the size of a
`blob_t` and is located _strictly_ outside the secured enclave memory
before operating on it by calling `oe_is_outside_enclave()`.

```diff
// WARNING: Portions of this code are intentionally flawed to demonstrate common
// pitfalls.
int ecall_with_user_check1(void* ptr) {

    blob_t* blob;

-   if (ptr == nullptr)
-       return -1;
+   // Ensure passed-in pointer is not null and the memory buffer is located
+   // strictly outside of the secured enclave memory.
+   if (!oe_is_outside_enclave(ptr, sizeof(blob_t)))
+       return -1;

    blob = (blob_t*)ptr;

    // Blobs to be rendered are limited to 4K.
    if (blob->size > 4096)
        return -1;

    return render_data(blob->data, blob->size);
}
```

## 1.2 Memory bounds: oe_is_within_enclave vs. oe_is_outside_enclave

Let's highlight a logical mistake that we've seen made in enclave applications.
Some have regarded the memory validation functions as boolean opposites of each
other, that is: `oe_is_within_enclave() == !oe_is_outside_enclave()`. This is
incorrect for several reasons.

To understand why these functions are _not_ boolean opposites, let's examine the
Open Enclave implementation for SGX as an example:
[memory.c](/enclave/core/sgx/memory.c).
There are three conditions that the functions validate:
1)	The pointer is not null.
2)	The bounding arithmetic operations do not wrap (that is, numerical
overflow).
3)	The buffer lies strictly within or outside of the secured enclave memory.

The first two conditions should make clear the pitfalls of considering the
function pair to be boolean opposites: If the pointer is null or the bounding
calculations overflow in a call to `oe_is_within_enclave()`, the function will
return `false`, which should _not_ be interpreted as "the buffer is strictly outside the
secured enclave memory" or `oe_is_outside_enclave() == true`.

The last condition is subtle: In some potentially malicious cases, the buffer
may be both partially within _and_ partially outside the secured enclave
memory, spanning the boundary between the two. (Attacks against enclaves
may use memory confusion to achieve overwrites of secured enclave memory, for
example.) Both functions will return `false` when the memory range spans the
boundary - another reason the functions are not boolean opposites.

<br />
<br />
<br />

## 1.3 TOCTOU or double fetch vulnerabilities

One class of vulnerabilities that custom marshaling code should protect against
is referred to as time-of-check/time-of-use, or TOCTOU. Another name for this
problem is "double-fetch". The problem arises when memory is shared across
security boundaries. As code validates input, it's critical that data is not
fetched twice (or, strictly, more than once), allowing a malicious untrusted
caller to change the data between the time-of-check and the time-of-use. Let's
examine our function:

```c++
// WARNING: Portions of this code are intentionally flawed to demonstrate common
// pitfalls.
int ecall_with_user_check2(void* ptr) {

    blob_t* blob;

    // Ensure passed-in pointer is not null and the memory buffer is located
    // strictly outside of the secured enclave memory.
    if (!oe_is_outside_enclave(ptr, sizeof(blob_t)))
        return -1;

    blob = (blob_t*)ptr;

    // Blobs to be rendered are limited to 4K.
    if (blob->size > 4096) //TOCTOU: First fetch
        return -1;

    return render_data(blob->data, blob->size); //TOCTOU: Second fetch
}
```
There's nothing wrong with the first fetch: The value is validated, and the
appropriate logic branch is taken. The problem arises when the code needs the
value again and reads it, once again, from the untrusted memory location outside
of the secured enclave memory. Between the first and subsequent fetch the value may have been
changed, neutralizing the size validation and possibly leading to some enclave
memory corruption that is helpful to the attacker. Let's protect the enclave by
"capturing" the values.

> When "capturing" data values in this context, it's important to protect
against the compiler's optimization, hence we use the `volatile` qualifier for
our local captured variables. Otherwise, the compiler might optimize-away our
local variables, removing the TOCTOU protection.

```diff
// WARNING: Portions of this code are intentionally flawed to demonstrate common
// pitfalls.
int ecall_with_user_check3(void* ptr) {

    blob_t* blob;
+   void* volatile captured_data;
+   volatile size_t captured_size;

    // Ensure passed-in pointer is not null and the memory buffer is located
    // strictly outside of the secured enclave memory.
    if (!oe_is_outside_enclave(ptr, sizeof(blob_t)))
        return -1;

    blob = (blob_t*)ptr;

+   // Capture blob descriptors to avoid TOCTOU problems.
+   captured_data = blob->data;
+   captured_size = blob->size;

    // Blobs to be rendered are limited to 4K.
-   if (blob->size > 4096) //TOCTOU: First fetch
+   if (captured_size > 4096)
        return -1;

-   return render_data(blob->data, blob->size); //TOCTOU: Second fetch
+   return render_data(captured_data, captured_size);
}
```

## 1.4 Ensure proper bounding of data buffers

Another element of marshaling code is ensuring, as complex structures are
parsed, that nested structures are also within the proper bounds. This is
especially important for internal functions like `render_data()` that may be
unaware that the memory is untrusted. Use the same techniques on the inner
structures that were used on the outer.

> A warning about legacy data-parsers: Take care when passing "hot" data to code
that may not have been written to parse maliciously crafted input. We have seen
cases where legacy code that parses self-formatting or self-referencing data was
used in new enclave applications. This can lead to significant vulnerabilities
if the data being parsed is still controlled by the ecall invoker, as may be the case
with custom marshaling. In the case of this sample code, as mentioned earlier,
`render_data()` parses "flat" data that is not nested nor self-referencing, so
it's safe (and performant) to pass it "hot" data that is controlled by the caller.
Care must be taken though, to avoid data-consistency and other app-level
integrity problems.

```diff
int ecall_with_user_check4(void* ptr) {

    blob_t* blob;
    void* volatile captured_data;
    volatile size_t captured_size;

    // Ensure passed-in pointer is not null and the memory buffer is located
    // strictly outside of the secured enclave memory.
    if (!oe_is_outside_enclave(ptr, sizeof(blob_t)))
        return -1;

    blob = (blob_t*)ptr;

    // Capture blob descriptors to avoid TOCTOU problems.
    captured_data = blob->data;
    captured_size = blob->size;

    // Blobs to be rendered are limited to 4K.
    if (captured_size > 4096)
        return -1;

+   // Ensure validity of nested structure
+   if (!oe_is_outside_enclave(captured_data, captured_size))
+       return -1;

+   // Data parsed by render_data is "flat", non-self-referencing.
    return render_data(captured_data, captured_size);
}
```
## 1.5 Updated enclave ecall with custom marshaling

Thanks for following along with us. Here's our updated ecall function that
marshals the parameter correctly for enclaves:
```c++
int ecall_with_user_check5(void* ptr) {

    blob_t* blob;
    void* volatile captured_data;
    volatile size_t captured_size;

    // Ensure passed-in pointer is not null and the memory buffer is located
    // strictly outside of the secured enclave memory.
    if (!oe_is_outside_enclave(ptr, sizeof(blob_t)))
        return -1;

    blob = (blob_t*)ptr;

    // Capture blob descriptors to avoid TOCTOU problems.
    captured_data = blob->data;
    captured_size = blob->size;

    // Blobs to be rendered are limited to 4K.
    if (captured_size > 4096)
        return -1;

    // Ensure validity of nested structure
    if (!oe_is_outside_enclave(captured_data, captured_size))
        return -1;

    // Data parsed by render_data is "flat", non-self-referencing.
    return render_data(captured_data, captured_size);
}
```

<br />
<br />
<br />

# 2. Handling secrets in enclave applications

Open Enclave is an SDK that helps developers build apps that will run inside a
hardware-based Trusted Execution Environment (TEE). At their core, TEEs protect
application code and data at runtime from the host environment. Without new,
hardware-implemented protections, a malicious or compromised host
would be able to modify code or read data. Any secrets managed by an
application during runtime would be at risk of exposure. The Open Enclave SDK
helps developers build applications that are protected from these threats.

> It's important to note that enclaves do not generally provide
_code confidentiality_. This is noteworthy in the context of this discussion
because, as will be discussed, hard-coded credentials in application code are to
be avoided&mdash;with or without enclave protections.

Enclaves provide new trust boundary protections that address old threats and
open new capabilities. But just as Open Enclave and TEEs shift the security
model, application developers must shift how they handle data, especially
secrets, like keys and passwords.
<br />
<br />
<br />

## 2.1 How _not_ to handle application secrets
Let's remind ourselves of a way _not_ to handle application secrets. A common
example of this well-discussed application weakness is described by
[CWE-798: Use of Hard-coded Credentials (4.4) (mitre.org)](https://cwe.mitre.org/data/definitions/798.html).
While application security is often a tradeoff between multiple factors and
broad edicts are not always appropriate, it's not controversial to simply say
that hard-coding credentials in application code _should not be done_.
<br />
<br />
<br />

## 2.2 The new, secure enclave way to handle application secrets

Enclaves provide two properties that enable applications to handle secrets
securely: 1) strong attestable identity, and 2) runtime protection of secrets in
memory. These two properties enable secure point-to-point secret transfers. When
applications are built with enclaves, all secret management should occur
dynamically _inside_ the enclave and through secure communications with trusted
sources, such as cloud service provider key vaults. By combining attestation
services with secure data services, it's possible to protect application
secrets, like access credentials.
