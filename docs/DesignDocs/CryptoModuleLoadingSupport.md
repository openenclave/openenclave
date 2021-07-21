Support for FIPS-Certified Cryptographic Module Loading in SGX Enclaves
======

Introduction
------------

An immediate requirement for developers to build production SGX enclaves with the OE SDK is
making the enclaves conform to industry standards. One such standard is Federal Information
Processing Standard 140 (FIPS 140). To be FIPS 140 compliant, an enclave must perform
certain cryptographic operations through a FIPS-validated module. The module usually
takes the form of a shared library. Once loaded, the module performs a series of self-tests
(also known as power-up self-tests, or POST), which validates both the integrity of the module
and the correctness of the cryptographic operations.

Objective
---------

This proposal aims to add the support of loading a FIPS-validated module in the OE
SDK in a timely manner, which allows an enclave to use the module and conforms to the FIPS requirement.
To this end, the proposed design should introduce minimal, incremental changes to the OE loader
that supports loading a single cryptographic module instead of general shared libraries.
More specifically, the design targets the implementation of a module based on
[SymCrypt](https://github.com/microsoft/SymCrypt).

While multiple loader implementations exist---e.g., the [dynamic linker](https://git.musl-libc.org/cgit/musl/tree/ldso/dynlink.c)
from musl---they may require more design considerations and code changes, which are not necessary for
supporting only the cryptographic module loading. However, such implementation would still
be ideal for the long term if we plan to generally support shared libraries loading in OE.
Unless there are more use cases show up, we leave this as future work and discuss possible options in
the [Longer-term Loader Design](#long-term-loader-design) section.

Note that the proposal targets SGX only, which introduces modifications to the loader that
OE has implemented. OP-TEE has its own loader, which is not part of OE, and therefore requires
different design. We will leave this as future work.

User Experience
------

- Module Usage

  A developer can use the functions from the module in an enclave program as those from
  static libraries. Also, the developer should expect the initialization (e.g., POST)
  and termination functions of the module are automatically invoked by the enclave runtime.

- Build

  The developer should compile the enclave program as usual. During the link-time, the developer
  should specify the module (e.g., `libsymcrypt.so`) in the command line as the following example.

  ```
  clang -o enclave enc.o libsymcrypt.so -loeenclave -loelibc -oecore
  ```

  Note that the module is required to be put under the same directory as the enclave binary.
  Moreover, both the `rpath` and `runpath` linker options *should not* be used.
  See [Module Lookup](#module-lookup) for more detail.
  The OE Make settings (i.e., `pkgconfig`) does not use these options by default and
  CMake settings explicitly opts out of these options by setting the `CMAKE_SKIP_RPATH` to `TRUE`.

- Sign

  The developer should sign the enclave binary as usual (see the following example). Note that the module
  is also required to be put under the same directory as the enclave binary.
  
  ```
  oesign sign -e enclave -c enclave.conf -k private.pem
  ```

- Run

  The developer should launch the enclave program as usual.

  ```
  ./host/host enclave/enclave.signed
  ```

  Again, this assumes that the `enclave/libsymcrypto.so` exists.
  For cases such as the shared library is not found in the enclave directory or the library
  is not supported (see the [Specification](#specification) for more detail), the loader
  aborts the execution and prints proper messages.

Specification
------

- The design supports a dynamically linked enclave binary against a *single* shared library.
- Instead of dynamically loading the shared libraries at the enclave runtime, the design statically
  loads the library into the enclave during the enclave creation.
- The design does not aim to generally support shared libraries; the design supports a shared library
  that shares similar properties as the Symcrypt-based module. Such properties include:
  - Using only the relocation types of `R_X86_64_GLOB_DAT`, `R_X86_64_JUMP_SLOT`, `R_X86_64_64`, and `R_X86_64_RELATIVE`.
  - Not using thread-local storage.
  - Optionally implementing initialization and termination functions.

  For a shared library with unsupported properties, the loader will explicitly error out.
- The design retains the existing behavior if the enclave is statically linked.
- The design targets SGX only.

Design
------

Instead of supporting dynamic loading or `dlopen`, which requires Enclave Dynamic Memory Management
(EDMM) in SGX2 that is not available yet, the idea of the design is supporting static loading
of a shared library (i.e., the Symcrypt module). More specifically, the OE loader loads the module along with
the enclave binary during the enclave creation as opposed to loading the library at the enclave runtime.
As a result, the module will be part of the enclave measurement (i.e., `MRENCLAVE`). The rest of the section details the design.

- Modified Enclave Memory Layout

  The modified enclave memory layout is as follows.
  The module is loaded in a contiguous memory region along with the enclave binary. In addition,
  the relocation pages now include the data from both the binary and the module. The rest
  of the layout remains unchanged.

  ```diff
  [PROGRAM PAGES]
      [CODE PAGES]
      [DATA PAGES]
  +[MODULE PAGES]
  +   [CODE PAGES]
  +   [DATA PAGES]
  [RELOCATION PAGES]
      [PROGRAM RELOCATION PAGES]
  +   [MODULE RELOCATION PAGES]
  [HEAP PAGES]
  [THREAD-PAGES]
      ...
  ```

- Module Loading

  An additional member `module` is added to the `oe_enclave_image_t` struct.

  ```diff
  struct _oe_enclave_image
  {
      oe_image_type type;

      /* Note: this can be part of a union distinguished by type if
       * other enclave binary formats are supported later */
      oe_enclave_elf_image_t elf;

  +   /* Pointer to the image of a module. */
  +   oe_enclave_elf_image_t* module;
  ```

  After loading the enclave binary, the host checks if the module is specified by the linker
  via looking up the entry with the `DT_NEEDED` tag in the `.dynamic` section.
  The tag is added by the linker for each shared library present in the command line.
  If specified, the host looks up the module under the same directory as the enclave and then loads the module
  into the memory (i.e., initializing the `module` member). Otherwise, the `module` remains `NULL`, which
  indicates that no module is loaded. If a `DT_NEEDED` entry is specified but the module is not
  found, the loader aborts the execution.
  
- Relocation Information Parsing

  During the process of the module loading, the loader pulls the relocation information from the `.rela.plt`
  section, which is specific for a shared library or dynamically linked application, in addition to the `.rela.dyn` table,
  which the loader previously supports. The loader combines the data from both sections into a single table and then
  adds the table to the relocation pages during the enclave creation.
  
- `.oeinfo` and Symbols Patching
  
  When the module is loaded, the loader updates the necessary information in the `.oeinfo` section, which includes:
  - `reloc_rva`: Fix up the RVA by adding the size of the module (i.e., `MODULE PAGES` in the enclave layout) to the original value.
  - `reloc_size`: Update the size by adding the size of the relocation data from the module (i.e., `MODULE RELOCATION PAGES` in the enclave layout) to the original value.
  - `heap_rva`: Fix up the RVA by adding the size of the module and that of its relocation data to the original value.

  In addition to the `.oeinfo` section, the loader also patches the two existing global symbols, `_reloc_rva` and `_reloc_size`, and
  a newly added one, `_module_info`, in the enclave binary. The loader updates the former two based on `reloc_rva` and `reloc_size`
  in the `.oeinfo` section. The new symbol, `_module info`, is a struct that includes the necessary information for an enclave to
  perform initialization and termination functions defined by the module. The definition of the struct is as follows.
  Note that the content of the struct will be part of the enclave measurement.
  
  ```
  typedef struct _oe_enclave_module_info
  {
      uint64_t base_rva;
      uint64_t init_array_rva;
      uint64_t init_array_size;
      uint64_t fini_array_rva;
      uint64_t fini_array_size;
  } oe_enclave_module_info_t;
  ```
  
  `base_rva`, the RVA of the module, equals the size of the enclave binary (i.e., the size of `PROGRAM PAGES` in the enclave layout).
  `base_rva` being `0` indicates that the enclave does not load the module.
  `init_array_rva` holds the rva of the `.init_array` section plus the `base_rva` while `init_array_size` equals to the size of the section.
  Similarly, `fini_array_rva` and `fini_array_size` hold the corresponding values of the `.fini_array` section.

- Relocation Processing

  Existing loader implementation, which targets only a statically linked enclave binary, does not patch any relocation information once
  loading them into the relocation pages. The enclave runtime only expects the entries with the `R_X86_64_RELATIVE` type in the relocation
  table and fixes up them by adding up the base address of the enclave.

  Supporting a dynamically linked enclave binary requires handling additional relocation types that are typically done by a dynamic linker.
  The design splits the job between the loader and the enclave runtime with the goal of keeping code changes to the latter minimum.
  More specifically, the loader looks up the relocation records with specific types and patches them accordingly. Patching effectively
  transforms a record into the type `R_X86_64_RELATIVE` such that the logic in the enclave runtime remains the same, avoiding introducing
  symbol look-up code to the enclave. The following details the patching process and the patching strategy for the supported relocation types.
  
  The design implements a function `_link_elf_image` that takes two parameters: `image` and `dependency`, both in the type of `oe_enclave_elf_image_t`.

  ```  
  static oe_result_t _link_elf_image(
      oe_enclave_elf_image_t* image,
      oe_enclave_elf_image_t* dependency)
  ```

  In addition, the design adds a member, `image_rva`, to the `oe_enclave_elf_image_t` struct that holds the RVA of an image: `0` for the
  image of the enclave binary, and the size of the enclave binary for the image of the module.
  
  ```diff
  struct _oe_enclave_elf_image
  {
      elf64_t elf;

      char* image_base;   /* Base of the loaded segment contents */
  +   uint64_t image_rva; /* RVA of the loaded segment contents */
      size_t image_size;  /* Size of all loaded segment contents */
  ```
  
  The `_link_elf_image` function iterates through the relocation table of the `image`. For the symbolic relocations, the function looks up the
  symbol, `symbol`, first in `image` (self-reference) and then in `dependency` (cross-reference), and patches the record according to its type. For the
  non-symbolic relocations, the function patches the record directly. Also, the function fixes up the `r_offset` field of the record by adding the
  `image->image_rva` to it such that the enclave runtime can correctly find the target address. This is due to that `r_offset` by default assumes the
  base address to be `0`, which is not the case for the module which is placed after the enclave binary.

  The patching strategy for supported types of relocation is as follows.
  - `R_X86_64_GLOB_DAT`:
     The symbolic type represents a cross- or self-reference to a global symbol. The former case only occurs in the enclave binary (e.g., using
     a global variable in the module) while the latter case only occurs in the module (e.g., using an `extern` variable defined in a header).
     
     - Patching
     ```
     r_info = (ELF64_R_SYM(r_info) << 32) | R_X86_64_RELATIVE;
     r_offset += image->image_rva;
     r_addend = image->image_rva + symbol.st_value;
     ```
  - `R_X86_64_JUMP_SLOT`:
     The symbolic type indicates a cross- or self-invocation to a function. The enclave binary can only have the cross-invocation (e.g., calling a
     function from the module) while the module can have both bases (e.g., using callback from the enclave binary and self-referencing functions).
     - Patching
     ```
     r_info = (ELF64_R_SYM(r_info) << 32) | R_X86_64_RELATIVE;
     r_offset += image->image_rva;
     r_addend = image->image_rva + symbol.st_value;
     ```
  - `R_X86_64_64`:
    The symbolic type represents a self-reference to a local symbol, which can only occur in the module.
     - Patching
     ```
     r_info = (ELF64_R_SYM(r_info) << 32) | R_X86_64_RELATIVE;
     r_offset += image->image_rva;
     r_addend += image->image_rva + symbol.st_value;
     ```
  - `R_X86_64_RELATIVE`:
    The only non-symbolic type associates with a relative address that requires a fix-up, which can only occur in the module.
     - Patching
     ```
     r_offset += image->image_rva;
     r_addend += image->image_rva;
     ```

  The loader invokes the function twice if the module is loaded, which patches the relocation records in
  both the enclave binary and the module.

  ```
  if (image->module)
  {
      ...
      OE_CHECK(_link_elf_image(&image->elf, image->module));
      OE_CHECK(_link_elf_image(image->module, &image->elf));
  }
  ```

  All the patches applies to the relocation information before they are loaded into the enclave and therefore are part of the enclave
  measurement. With the patching, the enclave runtime only needs to look up a record with the `R_X86_64_RELATIVE` type and fixes up the record by adding
  the base address of the enclave to it.

- Initialization and Termination Functions

  Initialization functions are essential for a module to invoke POST, meeting the FIPS requirement. The design supports such mechanisms via
  the previously mentioned `oe_enclave_module_info_t` struct. The design modifies the original `oe_call_init_functions` as follows.
  
  ```diff
  +static void _call_init_functions(
  +    void (**init_array_start)(void),
  +    void (**init_array_end)(void))
  {
       void (**fn)(void);
  +
  -    for (fn = &__init_array_start; fn < &__init_array_end; fn++)
  +    for (fn = init_array_start; fn < init_array_end; fn++)
  +    {
  +        (*fn)();
  +    }
  +}
  +
  void oe_call_init_functions(void)
  {
       extern void (*__init_array_start)(void);
       extern void (*__init_array_end)(void);
  +    const uint64_t start_address = (uint64_t)__oe_get_enclave_start_address();
  +    const oe_enclave_module_info_t* module_info = oe_get_module_info();
 
  +    if (module_info->base_rva)
       {
  +        uint64_t init_array_start = start_address + module_info->init_array_rva;
  +        uint64_t init_array_end = start_address + module_info->init_array_rva +
  +                                  module_info->init_array_size;
  +        _call_init_functions(
  +            (void (**)(void))(init_array_start),
  +            (void (**)(void))(init_array_end));
       }
  +
  +    _call_init_functions(&__init_array_start, &__init_array_end);
  }
  ```
  
  The enclave runtime conditionally invokes the initialization functions
  of the module according to the value of `module_info->base_rva` before invoking
  those of the enclave binary. The changes to the `oe_call_fini_functions` are similar
  but invoking the termination functions in reverse order.

  
Discussion and Future Work
-----------

### Module Lookup

An approach to eliminating the requirement of putting the module under the same directory as the enclave
binary is using the `rpath` or `runpatch` linker option. However, using these options results in injecting the
string of an absolute path to the `.dynstr` section, which is part of the enclave measurement. This would
make the enclave measurement environment-dependent even building with the same source files and libraries.
To avoid this, this current design explicitly asks developers not to use the `rpath` or `runpatch` option.

Alternatively, the loader can look up the module through an environment either extending the existing ones
(`LD_LIBRARY_PATH` on Linux and `PATH` on Windows) or creating a new one. We will leave this as future work.

### Long-term Loader Design

For the long term, it would be worth considering adopt a new loader design for OE. Possible options include:

- Intel SGX SDK Loader

  Unlike the OE loader that offloads the ELF parsing logic to the host, the
  [Intel SGX SDK's loader](https://github.com/intel/linux-sgx/blob/master/sdk/trts/linux/elf_parser.c) implements
  the ELF parsing logic in the enclave. This design eliminates the needs for the host to patch the relocation information
  and to pass relocation pages and an extra `oe_enclave_module_info_t` struct to the enclave.

- Musl Dynamic linker

  To generalize the support of shared libraries, it would be desirable for the loader to adopt the implementation
  of a dynamic linker (e.g., [musl's implementation](https://git.musl-libc.org/cgit/musl/tree/ldso/dynlink.c)).
  The prototype of this design can be found in the [feature branch](https://github.com/openenclave/openenclave/commits/feature/dynamic_binding).

Note that the two options can be complementary to each other, and we do not limit the design to these two.
Nevertheless, these options represent the design for better maintainability when there are the needs of supporting
more features to the loader. Such features include
- General shared libraries loading
- Protected Code Loader (PCL)
- `dlopen` (with the support of EDMM)

Given the use case, which this proposal targets, is only the cryptographic module, the design tries to add that support
with minimal efforts. We will leave the more detailed evaluation of the design as future work.

Author
------

- Ming-Wei Shih <mishih@microsoft.com>

