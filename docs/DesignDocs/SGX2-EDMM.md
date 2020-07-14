# SGX2 EDMM in Open Enclave SDK

Intel SGX2 on Icelake CPUs supports enclave dynamic memory management (EDMM),
which many applications of the Open Enclave SDK (OE) will want to take advantage
of. This document outlines the strategy for making these features available to
applications.

The key mechanism to support the dynamic addition of memory pages is the
`ENCLS[EAUG]` instruction, which allocates and zeroes a new memory page via
communication with the SGX driver. Before the enclave uses the new page, it
acknowledges its addition by issuing an `ENCLU[EACCEPT]` instruction for the
respective page address. Further, the `ENCLS[EMODPR]` and `ENCLU[EMODPE]`
instructions restrict or extend page permissions, respectively. Page type
changes (including page removal/trimming) are performed by the `ENCLS[EMODT]`
instruction.

## Heap allocation

We propose to add a new OCALL to OE enclaves which requests new memory pages
from the SGX driver (via `ioctl`), combined with an enclave function that, upon
return from the OCALL, accepts the new pages. This does not require handling of
signals or page faults and is easily integrated with memory managers like the
default dlmalloc, by pre-mapping a configurable maximum number of pages and
tracking the number of currently mapped pages. For performance reasons, we
propose to add a switchless version of the OCALL whenever
`OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS` is enabled:

    trusted {
      public oe_result_t oe_add_pages(size_t count);
      public oe_result_t oe_add_pages_switchless(size_t count) transition_using_threads;
    };

The pluggable allocator API then uses `oe_add_pages`, before allocating
additional pages, if necessary, before calling into `oe_allocator_*alloc`. The
maximum number of heap pages (and perhaps other parameters like page
permissions) are passed to `oe_allocator_init`.

Applications that run a full OS kernel, for instance SGX-LKL, need to know about
the size and layout of their address space and can therefore effectively use
dynamic region allocation, which the SGX driver supports by tracking memory
regions in the SGX driver. It automatically grows the heap by allocating a
configurable number of pages upon request for a particular (unmapped) page.
Dynamic regions are most conveniently declared as an initialization parameter to
`oe_allocator_init` again.

The permissions (R/W/X) of pages can be modified dynamically. Permissions of
mapped pages are restricted by the `ENCLS[EMODPR]` instruction, which is a
privileged instruction (ring 0) that the host executes. Similarly, permissions
are extended by the `ENCLU[EMODPE]` instruction, which the enclave executes.
OE's current pluggable allocators do not support permission changes. We propose
to add a single, easy to use function to change (both restrict and extend) the
page types of allocated memory, e.g.

    oe_result_t oe_sgx_set_page_permissions(void* address, bool R, bool W, bool X);

We expect that OE applications will usually want the R bit enabled by default,
but some applications require the X bit to be set and others may chose to
relinquish the W flag to avoid accidental modification of memory pages. (One of
the reasons that SGX-LKL is forced to use a custom version of OE, is that the
memory permissions are not configurable at signing, launching, or run time; see
also [#3561](https://github.com/openenclave/openenclave/pull/3561).)

## Extensions

SGX2 supports "lazy" addition of heap and stack memory by triggering and
catching page faults. However, we believe that most near-term applications will
not have a strict requirement for this, so we propose not to implement this in
OE for now. (Intel provides a sketch of a modification to dlmalloc's `sbrk`,
which automates heap expansion [1].)

Further, SGX2 supports the dynamic creation of thread control structures (TCS)
by changing the type of allocated pages (via the `ENCLS[EMODT]` instruction).
While fully dynamic threading is perhaps not a strict requirement for most
applications, it is a worthwhile consideration to add a generic OE function that
allows applications to easily change page types, should they have a need to do
so.

## Signing

The new minimum and maximum memory size settings are signed and attested,
therefore support for them is added to `oe_enclave_size_settings_t`:

    typedef struct _oe_enclave_size_settings
    {
        uint64_t num_heap_pages;
        uint64_t num_stack_pages;
        uint64_t num_tcs;

        uint64_t min_heap_pages, max_heap_pages;
        uint64_t min_stack_pages, max_stack_pages;
        uint64_t min_tcs, max_tcs;
    } oe_enclave_size_settings_t;

This automatically adds them to the enclave properties in the `.oeinfo` section.
The parser for configuration files for the `oesign` tool is extended
accordingly. While perhaps not necessary immediately, this should include
minimum and maximum stack and TCS settings in preparation for a future extension
to dynamic stack and TCS page addition.

# References

[1] Bin (Cedric) Xing, Mark Shanahan, Rebekah Leslie-Hurd: Intel Software Guard
Extensions (Intel SGX) Software Support for Dynamic Memory Allocation inside an
Enclave. HASP@ISCA 2016: 11:1-11:9
[[link](https://caslab.csl.yale.edu/workshops/hasp2016/HASP16-17.pdf)]
