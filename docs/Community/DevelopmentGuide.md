Development Guide
=================

Coding Conventions
------------------

* **DO** use fixed length types defined in `include/openenclave/types.h` instead
  of language keywords determined by the compiler (e.g., `int64_t, uint8_t`, not
  `long, unsigned char`).

* **DO** use `const` and `static` and visibility modifiers to scope exposure of
   variables and methods as much as possible.

* **DO** use doxygen comments, with \[in,out\]
  [direction annotation](http://www.doxygen.nl/manual/commands.html#cmdparam) in all public API
  headers. This is also encouraged, but not strictly required, for internal API
  headers as well.

* **DO** disable doxygen documentation for elements that are not in the public
  API as described [here](./refman/doxygen-howto.md#disable-doxygen).

* **DON'T** use global variables where possible.

* **DON'T** use abbreviations unless they are already well-known terms known by
  users (e.g., "app", "info"), or are already required for use by developers (e.g.,
  "min", "max", "args").  Examples of bad use would be `num_widgets` instead of
  `widget_count`, and `opt_widgets` instead of `option_widgets` or `optional_widgets`.

* **DON'T** use the same C function name with two different prototypes across
  the SDK (e.g., for host vs. enclave) where possible.  A notable exception
  is for edger8r-generated APIs that generate a host-side API that includes
  an enclave argument in addition to the arguments for the enclave-side API,
  but all other arguments are still identical.

Style Guide
-----------

### Automated Formatting with `clang-format`

For all C/C++ files (`*.c`, `*.cpp` and `*.h`), we use `clang-format` (specifically
version 3.6) to apply our code formatting rules. After modifying C/C++ files and
before merging, be sure to run:

```sh
$ ./scripts/format-code
```

This allows us to apply formatting choices such as the use of [Allman style](
http://en.wikipedia.org/wiki/Indent_style#Allman_style) braces and the 80
character column width consistently.

Please stage the formatting changes with your commit, instead of making an extra
"Format Code" commit. Your editor can likely be set up to automatically run
`clang-format` across the file or region you're editing. See:

- [clang-format.el](https://github.com/llvm-mirror/clang/blob/master/tools/clang-format/clang-format.el) for Emacs
- [vim-clang-format](https://github.com/rhysd/vim-clang-format) for Vim
- [vscode-cpptools](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools)
  for Visual Studio Code

The [.clang-format](../.clang-format) file describes the style that is enforced
by the script, which is based off the LLVM style with modifications closer to
the default Visual Studio style. See [clang-format style options](
http://releases.llvm.org/3.6.0/tools/clang/docs/ClangFormatStyleOptions.html)
for details.

### License Header

The following license header **must** be included at the top of every code file:

```
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
```

It should be prefixed with the file's comment marker. If there is a compelling
reason to not include this header, the file can be added to
`.check-license.ignore`.

All files are checked for this header with the script:

```sh
$ ./scripts/check-license
```

### Naming Conventions

Naming conventions we use that are not automated include:

1. Use `lower_snake_case` for variable, member/field, and function names.
2. Use `UPPER_SNAKE_CASE` for macro names and constants.
3. Prefer `lower_snake_case` file names for headers and sources.
4. Prefer full words for names over contractions (i.e., `memory_context`, not
   `mem_ctx`).
5. Prefix names with `_` to indicate internal and private fields or methods
   (e.g., `_internal_field, _internal_method()`).
6. The single underscore (`_` ) is reserved for local definitions (static,
   file-scope definitions).
   e.g., static oe_result_t _parse_sgx_report_body(..).
7. Prefix `struct` definitions with `_` (this is an exception to point 6), and always create a `typedef` with the
   suffix `_t`.  For example:
```c
typedef struct _oe_private_key
{
    uint64_t magic;
    mbedtls_pk_context pk;
} oe_private_key_t;
```
8. Prefix Open Enclave specific names in the global namespace with `oe_` (e.g.,
   `oe_result_t, oe_call_enclave`).

Above all, if a file happens to differ in style from these guidelines (e.g.,
private members are named `m_member` rather than `_member`), the existing style
in that file takes precedence.

Note that we _no longer_ use `CamelCase` nor double underscores (`__`), but you
may find remnants and so again should prefer the local style. This is especially
the case for classes, which are still using `PascalCase`. For now, follow the
existing style. The project Committers prefer to fix style issues in bulk using
automation, so avoid submitting PRs intended to fix only a few instances of the
inconsistent style.

For other files (`*.asm`, `*.S`, etc.) our current best guidance is consistency:

- When editing files, keep new code and changes consistent with the style in the
  files.
- For new files, it should conform to the style for that component.
- For new components, any style that is broadly accepted is fine.

### Example File

Excerpt from `enclave/key.c`:

```c
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "key.h"
#include <openenclave/internal/safecrt.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/crypto/hash.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include "pem.h"

typedef oe_result_t (*oe_copy_key)(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copy_private_fields);

bool oe_private_key_is_valid(
    const oe_private_key_t* private_key,
    uint64_t magic)
{
    return private_key && private_key->magic == magic;
}

oe_result_t oe_private_key_init(
    oe_private_key_t* private_key,
    const mbedtls_pk_context* pk,
    oe_copy_key copy_key,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!private_key || (pk && !copy_key) || (copy_key && !pk))
        OE_RAISE(OE_INVALID_PARAMETER);

    private_key->magic = 0;

    if (pk && copy_key)
        OE_CHECK(copy_key(&private_key->pk, pk, true));
    else
        mbedtls_pk_init(&private_key->pk);

    private_key->magic = magic;

    result = OE_OK;

done:
    return result;
}

void oe_private_key_release(oe_private_key_t* private_key, uint64_t magic)
{
    if (oe_private_key_is_valid(private_key, magic))
    {
        mbedtls_pk_free(&private_key->pk);
        oe_secure_zero_fill(private_key, sizeof(oe_private_key_t));
    }
}

bool oe_public_key_is_valid(const oe_public_key_t* public_key, uint64_t magic)
{
    return public_key && public_key->magic == magic;
}

oe_result_t oe_public_key_init(
    oe_public_key_t* public_key,
    const mbedtls_pk_context* pk,
    oe_copy_key copy_key,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!public_key || (pk && !copy_key) || (copy_key && !pk))
        OE_RAISE(OE_INVALID_PARAMETER);

    public_key->magic = 0;

    if (pk && copy_key)
        OE_CHECK(copy_key(&public_key->pk, pk, false));
    else
        mbedtls_pk_init(&public_key->pk);

    public_key->magic = magic;

    result = OE_OK;

done:
    return result;
}

void oe_public_key_release(oe_public_key_t* public_key, uint64_t magics)
{
    if (oe_public_key_is_valid(public_key, magic))
    {
        mbedtls_pk_free(&public_key->pk);
        oe_secure_zero_fill(public_key, sizeof(oe_public_key_t));
    }
}

/*
**==============================================================================
**
** _map_hash_type()
**
**==============================================================================
*/

static mbedtls_md_type_t _map_hash_type(oe_hash_type_t md)
{
    switch (md)
    {
        case OE_HASH_TYPE_SHA256:
            return MBEDTLS_MD_SHA256;
        case OE_HASH_TYPE_SHA512:
            return MBEDTLS_MD_SHA512;
        case __OE_HASH_TYPE_MAX:
            return MBEDTLS_MD_NONE;
    }

    /* Unreachable */
    return 0;
}
```
