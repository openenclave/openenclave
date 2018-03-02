Development Guide
=================

Coding Conventions
------------------

* **DO** use fixed length types defined in include/openenclave/types.h instead of
   language keywords determined by the compiler (e.g. `int64_t, uint8_t`, not
   `long, unsigned char`).

* **DO** use `const` and `static` and visibility modifiers to scope exposure of
   variables and methods as much as possible. 
   
* **DON'T** use global variables where possible.

Style Guide
-----------

For all C/C++ files (*.c, *.cpp and *.h), we use clang-format (version 3.6+) to
ensure code formatting. After modifying C/C++ files and before merging, be sure
to run:

```
$ ./scripts/format-code
```
This allows us apply formatting choices such as the use of [Allman style](
http://en.wikipedia.org/wiki/Indent_style#Allman_style) braces and the 80
character column width consistently.

The [.clang-format](../.clang-format) file describes the style that is enforced
by the script, which is based off the LLVM style with modifications closer to
the default Visual Studio style. See [clang-format style options](
http://releases.llvm.org/3.6.0/tools/clang/docs/ClangFormatStyleOptions.html)
for details. 

Naming conventions we use that are not automated include:

1. Use `camelCase` for variable and field names.
2. Use `PascalCase` for function, type, struct and class names.
3. Use `ALL_CAPS` for macro names.
4. Prefer `all_lowercase` file names for headers and sources.
5. Prefer full words for names over contractions (e.g. `MemoryContext`, not
   `MemCtx`).
6. Prefix names with `_` to indicate internal and private fields or methods
   (e.g. `_internalField, _InternalMethod()`).
7. Prefix Open Enclave specific names in the global namespace with `OE_` 
   (e.g. `OE_Result, OE_CallEnclave`).

Above all, if a file happens to differ in style from these guidelines (e.g. 
private members are named `m_member` rather than `_member`), the existing style
in that file takes precedence.

For other files (.asm, .S, etc.) our current best guidance is consistency:

- When editing files, keep new code and changes consistent with the style in the files.
- For new files, it should conform to the style for that component.
- For new components, any style that is broadly accepted is fine.

### Example File:

``enclave/hoststack.c:``
```
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/utils.h>
#include <openenclave/enclave.h>
#include "td.h"

void* OE_HostAllocForCallHost(size_t size, size_t alignment, bool isZeroInit)
{
    TD* td = TD_Get();

    /* Fail if size is zero or no thread data object */
    if (size == 0 || !td)
    {
        OE_Abort();
        return NULL;
    }

    /* Fail if host stack pointer is not aligned on a word boundary */
    if (OE_RoundUpToMultiple(td->host_rsp, sizeof(uint64_t)) != td->host_rsp)
    {
        OE_Abort();
        return NULL;
    }

    /* Round size request to a multiple of the word size */
    size = OE_RoundUpToMultiple(size, sizeof(uint64_t));

    /* Set minimum alignment */
    if (alignment == 0)
        alignment = sizeof(uint64_t);

    /* Fail if alignment is not a multiple of the word size */
    if (OE_RoundUpToMultiple(alignment, sizeof(uint64_t)) != alignment)
    {
        OE_Abort();
        return NULL;
    }

    size_t total_size = size + alignment;

    td->host_rsp -= total_size;

    void* ptr = (void*)td->host_rsp;

    /* Align the memory */
    ptr = (void*)OE_AlignPointer(ptr, alignment);

    /* Clear the memory if requested */
    if (ptr && isZeroInit)
        OE_Memset(ptr, 0, size);

    return ptr;
}
```
