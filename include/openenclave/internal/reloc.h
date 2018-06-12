// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_RELOC_H
#define _OE_RELOC_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/* Same layout as Elf64_Rela (see elf.h) */
typedef struct _oe_reloc
{
    uint64_t offset;
    uint64_t info;
    int64_t addend;
} oe_reloc_t;

OE_EXTERNC_END

#endif /* _OE_RELOC_H */
