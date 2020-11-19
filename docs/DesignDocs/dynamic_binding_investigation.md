# Dynamic Linking Support for SGX Enclave Loading

## Overview

This document captures the notes and refinement of implementation considerations for implementing dynamic binding as described in [OE SDK Dynamic Binding](https://github.com/openenclave/public-talks/blob/master/OE%20SDK%20Dynamic%20Binding%2011-10-2020.pptx).
It covers the investigation of the refactoring needed to converge towards a dynamic binding model that is compatible with MUSL libc and shifting the responsibility of using the ELF metadata in loaded program segements directly in the enclaves that may pave the way for future work such as dynamic loading in the enclaves and expanded support for ELF loading features.

## Porting MUSL dynamic loading code into OE

The primary thrust of the investigation is to understand how OE loading differs from a standard (or close to standard) `ldso` loader implementation, such as the one MUSL libc provides, and whether pieces of that implementation can be reused to simplify the OE loader implementation for dynamic binding. The rest of this document discusses changes in relation to the [3rdparty/musl/musl/ldso/dynlink.c](3rdparty/musl/musl/ldso/dynlink.c) implementation. The rest of this document assumes that the reader will be familiar with the functions and data structures referenced from that source file.

A naive high level goal might be to replace the entire OE loader stack with a lightly refactored version of the MUSL loader, and in doing so, illustrate what the key differences in behavior and kinds of support we need to consider for the OE dynamic binding implementation.
For example, comparing the feature/dynamic_binding prototype implementation of the `link_info` struct in [include/openenclave/internal/link.h](include/openenclave/internal/link.h):

```c
typedef struct _oe_module_link_info
{
    /* Module image rva */
    uint64_t base_rva;  // NOTE: Maps to dso.base

    /*
     * NOTE: The MUSL implementation never actually goes through section data
     * directly and doesn't touch the .rela.dyn section. Instead, it does the
     * look-ups through the decoded dynamic table as part of reloc_all directly
     */

    uint64_t reloc_rva;
    uint64_t reloc_size;

    /*
     * NOTE: Similarly, MUSL doesn't special case .tbss or .tdata, but it's
     * unclear where this is handled. It seems like this should be handled as
     * part of what MUSL does to setup and track the tls_image per DSO.
     */

    /* Thread-local storage .tdata section */
    uint64_t tdata_rva;
    uint64_t tdata_size;
    uint64_t tdata_align;

    /* Thread-local storage .tbss section */
    uint64_t tbss_size;
    uint64_t tbss_align;

    /*
     * NOTE: Like in the .rela.dyn case, MUSL instead looks these up on-demand during
     * libc initialization via the dynamic table and not the section headers.
     */

    /* Global initialization .init_array section */
    uint64_t init_array_rva;
    uint64_t init_array_size;

    /* Global destructors .fini_array section */
    uint64_t fini_array_rva;
    uint64_t fini_array_size;

} oe_module_link_info_t;

```

The key functions we will be interested in for the OE SDK context will be limited to:

- `dso` struct and its member types
- `__dls3()` as the high level "equivalent" of `oe_load_elf_enclave_image()`
- `load_library()` and `map_library()` as the high level "equivalent" of `_load_elf_image()`
- `alloc_all()` as a potential replacement for custom `apply_allocations()`

## Summary of existing `oe_create_enclave()` codepath and integration points with DSO loading

`oe_create_enclave()` [create.c]
- `oe_sgx_initialize_load_context()` sets up attribute flags. load type, load state
- `oe_sgx_build_enclave()` with context
  - `oe_load_enclave_image()` loads the primary enclave `oe_enclave_image_t` struct from path
    - `oe_enclave_image_t` contains `oe_enclave_elf_image_t` specifically which encapsulates parsed ELF info
      - Effectively, the first half of `__dls3()` and its `load_library()` pieces to replace `oe_load_enclave_image()`
      - This would also incorporate the linking dependnecy walk changes currently implemented as part of the `_patch_elf_image()` phase in the prototype.
      - Need to convert the output of the process into compatible inputs for the existing enclave add data methods after the `oe_sgx_create_enclave()` call, after the sizing is determined.
  - `_calculate_enclave_size()` relies on `oe_enclave_image_t.calculate_size()` to get total size of all images, which should continue to be derivable from DSO properties.
  - `oe_sgx_create_enclave()` is called with enclave size (ELRANGE) and calculated loaded enclave pages size
  - `oe_enclave_image_t.sgx_patch()` calls
    - `_patch_elf_image()` which calls
      - `_link_elf_images()` recursively, this is where the bulk of the fixups happen on the host side
      - `_patch_link_info_array()` similarly recursively walks the pre-digested `oe_module_link_info` structs on each image to populate the global `oe_linked_modules` via `_write_link_info()`
      - These likely could be combined into a single dependency walk with the more complicated DSO-like data structure for the single pass.

In comparison to `__dls3` in MUSL libc, the `dso` struct is loaded directly by `map_library` from the file descriptor, so there's no separation as exists between the `oe_enclave_elf_image_t` and the `oe_module_link_info_t`, it just gets pulled in during the initial load rather than the patching. Per the analysis of `oe_module_link_info_t` earlier, _it is desirable if we could simplify and consolidate out all of necessary information into a single data structure with minimum redundancy._

## Breaking down `__dls3`

### Behaviors to adopt:

- Initialize the static `head`, `tail` and `syms_tail` members
  - Should convert these into passed parameters instead of static globals.
- Initialize the static `tls_head` and `tls_tail` members
  - These are carried on the static global `libc` struct, which should probably be merged into the global static state equivalent for OE (e.g. `oe_dso_load_state_t` might need `tls_tail` and also the mapping of that to `libc.tls_head`).
    - The use for this seems to be primarily for the dynamic loading scenario where the TLS information needs to be updated, so we might not have to implement this yet.
  - The DSO also carries individually its `tls` member with an ID based on the count of the TLS. This likely replaces the TLS info carried in `link_info` into the enclave today.
- Build the linked list of symbols for each DSO via `add_syms`, which is referenced in `do_relocs`
  - Because we don't support dynamic loading, the `p->syms_next`/`syms_tail` states are effectively identical to `p->next`/`tail` DSO list and may not need to be added separately for `do_relocs`.
  - `find_syms` would need to be modified for OE to look at the normal DSO linked list instead.

### Unsupported behaviors:

- Will not provide Linux compatible `errno` semantics (more internally consistent for OE to use `oe_result_t` and flow control patterns).
- Will not depend on kernel set `aux` vector
- Will not support environmental variables like `LD_PRELOAD` and `LD_LIBRARY_PATH`
  - By extension, will not support the preloading behavior for intercepting symbols, or the Linux standard .so path search order.
- Will not have to differentiate whether main program was already loaded by the kernel or if
  - Enclave loading treats primary enclave binary load the same as dependencies because it does not need to bootstrap the `ldso` loading process itself (i.e. `__dls2` and previous steps).
  - We ignore the entire ldd mode codepath and command line argument handling.
- Will not support `DL_FDPIC` which is specific to the SuperH RISC architecture we don't support.
  - This elides the usage of `makefuncdescs` and the `loadmap` member.
- Will not attempt to reclaim unused pages from the mapping of `ldso` or the primary app DSO.
  - This would require modifications to malloc to accept and track the pages as usable heap pages, which is difficult to support with pluggable allocators.
- Will not support attaching to `vdso` as it doesn't make sense for enclave apps.
- Will not support the same debug state management as MUSL (i.e. use of `debug` struct and `_dl_debug_state()`)
  - **OPEN: Skip handling of `DT_DEBUG` dynamic section type.**
    - `DT_DEBUG_INDIRECT` is a build flag set by architecture, and is explicitly set to 0 for the MIPS architectures.
      - We shouldn't have to handle the case where `!DT_DEBUG_INDIRECT` and `DT_DEBUG` section exists since we don't handle target MIPS.
    - When it is supported (other arches and `DT_DEBUG_INDIRECT` exists in ELF), it's not clear what we would do with the information there for enclave debugging.
- Check for `malloc` symbol replacement and flag it so that MUSL implementation of `calloc`/`memalign` family of functions can harden against incomplete replacement.
- Will not attempt to set `runtime` flag on completion to indicate completion of bind-on-load
  - OE SDK will not support dynamic loading for enclaves right now, and certainly not from the host side loader code, so the distinction is meaningless.
- Will not jump to the entry point for the app as indicated by the `aux` vector
  - OE will track the entry point for call in later though.
- Will not invoke `reloc_all` at this point
  - OE will only invoke relocation on the enclave side ECall
  - The goal is to have the `dso` objects set up so that the logic for `reloc_all` and `do_relocs` can be pretty much ported directly to the enclave.
- Will not support `RELRO` since we cannot change page protections after relocation in the enclave (at least not until EDMM).
- `TLS_ABOVE_TP` handling of TLS offset
  - This is needed for aarch64, but is not used in x86_64, will not be supported in the initial implementation.

## Breaking down `load_library`

### Behaviors to adopt:

- If provided full path, load from path, otherwise, check the linked list of all loaded DSO based on shortname and return that if already loaded (support circular references)
  - Because the duplicate load check depends on shortnames and some DSO are loaded directly from the pathname, need to always set up the shortname as well.
  - `load_library` does this lazily only when it detects a loaded file has the same device (drive) and inode as an already loaded DSO, but this approach does not work on Windows since inodes are undefined on NTFS/FAT per Windows [`_stat64`](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/stat-functions?view=msvc-160)
- Allocate storage for new DSO, similar to what we do for the `image` and `link_info` objects today in OE.

### Unsupported behaviors:

- `ldd_mode` (OE loader does not need to support CLI loading of arbitrary .so)
- Load from pathname with `O_CLOEXEC` flag (irrelevant, not loading as executable)
- Search path for loading dso with short name (replace with OE-specific lookup)
  - In general, no support for standard dynamic linker `RPATH` behaviors, ignore both `DT_RPATH` and `DT_RUNPATH` dynamic table entries.
- `TLS_ABOVE_TP` handling of TLS offset
  - This is needed for aarch64, but is not used in x86_64
- Runtime behaviors, such as growing the Dynamic Thread Vector (DTV)
  - i.e. when allocating space for a dynamically loaded DSO, it needs to reserve space for all existing threads to get a copy of the new TLS plus the extended DTV with an additional slot for the just loaded DSO.
    - See [Runtime Allocation of Thread-Local Storage](https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/6n33n7fei/index.html)
    - [ ] MUSL uses `tls_cnt+3` for the per thread size in this calculation...why +3?
- Checking that the loader doesn't reload itself (name of the ldso module) or reserved library names (`lib{c|pthread|rt|m|dl|util|xnet}`)
  - After `map_library`, checking for the `__libc_start_main` && `stdin` symbols explicitly to verify that the mapped library is not another copy of libc to prevent MUSL/glibc interposition hacks. (corner case for enclave scenario, primary loading module is not itself libc)

## Breaking down `map_library`

### Behaviors to adopt:

- Cache DSO pointers for `dyn` and `tls_image` and its properties (`tls.align`, `tls.len`, `tls.size`)

### Unsupported behaviors:

- Will not support `DL_FDPIC` or `DL_NOMMU_SUPPORT' which are specific to the SuperH architecture we don't support.
  - This elides setting up the maps for the `loadmap` member.
- Will not support `PT_GNU_RELRO` since we cannot change page protections after relocation in the enclave.
- Will not support `PT_GNU_STACK` since we lock the configuration of the stack to the authored enclave stack size and do not allow setting RWX stack.
- Will not support `DT_TEXTREL` where relocation entries may request modifications to a non-writable segment.
  - MUSL deals with this by changing the segment protections to RWX which is undesirable for enclave loads.

## Breaking down `reloc_all`

### OE Specific behaviors:

- The `dso->sym_next` members are only populated inside the enclave as opposed to on the host side:
  - MUSL populates this immediately after the `load_deps()` call.
  - The `sym_next` linked list is only used inside the enclave as part of symbol lookup for applying relocations.
  - To avoid having to convert the extra `sym_next` pointer to an RVA so that it is stable for enclave measurement, then converting it back to an address pointer in the enclave, OE just populates it inside the enclave once and measures it as `NULL` during load.
    - The `sym_next` chain is deterministic given the structure of the `dso` linked list, so no information is lost.
### Behaviors to adopt:

- Caller runs `reloc_all` on dependencies first, then the main application
  - **OPEN: Not clear that this is necessary if OE doesn't support primary enclaves using copy relocations anyway**

### Unsupported behaviors:

- Will not support `NEED_MIPS_GOT_RELOCS`, since OE doesn't support MIPS architectures.
- Will not support `RELRO` handling to lock the relocations after update since we cannot change page protections after relocation in the enclave (at least not until EDMM).
- Will not support lazy binding.
- Will not support `TLSDESC_BACKWARDS` although this may be needed in the future for ARM architecture.
## Additional Notes

- Our implementation doesn't support legacy INIT/FINI (see `do_init_fini()` line 1309 for an example) as we only look for `DT_INIT_ARRAY`/`DT_FINI_ARRAY` currently.
- On `__libc_start_init()`, `do_init_fini()` starts with `tail` rather than head, and walks `p->prev` linked list to the `head`
- libc/link.c implementation of `dl_iterate_phdr` assumes a single binary and doesn't correctly reflect all information needed by `dl_phdr_info`. It also needs to be replaced the MUSL dynlink.c implementation for correctness.
- While it's tempting to replace the less efficient `memcpy` implementation of `_stage_image_segments` with the `mmap` version in `map_library` it doesn't look like it translates well into a Windows compatible implementation
  - The closest equivalent is `CreateFileMapping` that will not use `fd` which needs a change to the function signatures to support. Also need to investigate if `CreateFileMapping` provides the same semantics where virtual memory allocation can be reserved, but modified later on commit in the same way that the code tries to `mmap` twice for Linux.
- `_dls3` specifically calls `reloc_all` on all dependency DSOs first (`reloc_all(app.next)`) and relocates the app DSO last to account for copy relocations (`reloc_all(&app)`).
  - This may not be relevant to us since we expect that the primary enclave binary is compiled with `-fPIE`, and it should not contain copy relocations. Need to verify this, but it's probably easier just to follow this same usage pattern when updating OE's `apply_relocations`

## Open questions

- [ ] `decode_dyn()` does not appear to look up `DT_DYNSYM` or `DT_DYNSTR` which OE does rely on for the global symbols.Need to add this or figure out why it's not used in MUSL.
