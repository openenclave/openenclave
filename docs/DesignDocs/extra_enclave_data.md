Extra SGX enclave data
======================

This document proposes a mechanism for injecting "extra enclave data" into the
SGX enclave memory image. The extra data is signed and measured as part of the
enclave memory image and is therefore covered by MRENCLAVE.

## Motivation

This mechanism may be used by applications with memory requirements that cannot
be met by the Open Enclave read-write heap. Examples include:

- Read-executable pages intended for loaded program segments.
- Additional guard pages used to protect user-defined stacks.
- Read-only pages intended for non-writable program data.
- Inclusion of trusted hashes.
- Inclusion of trusted public keys.
- Read-write-executable pages for user-defined program loaders.

This feature allows an application to manage a contiguous region or memory,
controlling its content and the permissions of each of its pages.

## User Experience

Users may add additional pages by defining a "hook" that is called by the
OE SGX enclave loader. This hook calls a special function for adding pages.
For example, an Open Enclave host application may define the following function
to inject one read-write-executable page.

```
oe_result_t oe_load_extra_enclave_data_hook(void* arg, uint64_t baseaddr)
{
    __attribute__((__aligned__(PAGE_SIZE)))
    uint8_t page[PAGE_SIZE];
    uint64_t flags = 0;

    memset(page, 0, sizeof(page));
    flags |= SGX_SECINFO_REG;
    flags |= SGX_SECINFO_R;
    flags |= SGX_SECINFO_W;
    flags |= SGX_SECINFO_X;
    const bool extend = true;
    oe_load_extra_enclave_data(arg, 0, page, flags, extend);

    return OE_OK;
}
```

This function calls **oe_load_extra_enclave_data()**, which adds the page to
the enclave memory image. The new page will be injected just before the Open
Enclave heap (and can be located accordingly).

The following enclave function, retrieves the page relative to the heap.

```
/* obtain a pointer to the final page of extra enclave data */
void* get_extra_enclave_data_page(void)
{
    extern void* __oe_get_heap_base();
    return (uint8_t*)__oe_get_heap_base() - OE_PAGE_SIZE;
}
```

## Specification

### APIs

This design adds two undocumented functions.

- oe_load_extra_enclave_data_hook()
- oe_load_extra_enclave_data()

The **oe_load_extra_enclave_data_hook()** is defined as a weak function that
can be overridden by a strong definition in the host application. This function
is called twice: once for determining the total size of the extra enclave data
and again to load the data into the SGX enclave memory image. The definition is
shown below.

```
oe_result_t oe_load_extra_enclave_data_hook(
    void* arg,          // passed on to oe_load_extra_enclave_data()
    uint64_t baseaddr); // offset to extra enclave data (zero on first call)
```

The host applications calls **oe_load_extra_enclave_data()** to add an extra
page of enclave data. The function is defined as follows.

```
oe_result_t oe_load_extra_enclave_data(
    void* arg,          // forwarded from oe_load_extra_enclave_data_hook()
    uint64_t vaddr,     // offset of new page (within extra enclave data)
    const void* page,   // pointer to new page
    uint64_t flags,     // flags (example: SGX_SECINFO_REG, SGX_SECINFO_W)
    bool extend)        // whether to measure the page contents
```

### Memory layout

The following figure shows the enclave memory layout with the extra enclave
data region.

```
    +----------------+
    | program-pages  |
    +----------------+
    | extra pages    |
    +----------------+
    | heap pages     |
    +----------------+
    | thread-1 pages |
    +----------------+
    | ...            |
    +----------------+
    | thread-n pages |
    +----------------+
```

The "extra pages" are injected between the program pages and the heap pages.

## Non-requirements

### Debugger extensions

The extra enclave memory region may contain an executable image (e.g., ELF).
Debugger extensions would be needed to support debugging of this executable.
This requirement will be treated separately in a future design.

### Segment demarcation

Determining the location of segments within the extra enclave data memory region
is left to the user. For example, if this region contains three segments, the
user will have to provide a mechanism for finding these segments. We suggest
appending a trailer page to each segment. Then the final segment's trailer page
can be obtained relative to the start of the heap. The segments can then be
traversed by skipping backwards over the trailer pages. A typical trailer page
may contain the size and index of the segment and perhaps the name or type of
the segment. In some cases, the trailer page might contain additional data (such
as the hash of an external file).

## Authors

Mike Brasher (mikbras@microsoft.com)
