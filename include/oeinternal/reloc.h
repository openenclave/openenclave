#ifndef _OE_RELOC_H
#define _OE_RELOC_H

#include "../oecommon/defs.h"
#include "../oecommon/types.h"

OE_EXTERNC_BEGIN

/* Same layout as Elf64_Rela (see elf.h) */
typedef struct _OE_Reloc
{
    oe_uint64_t offset;
    oe_uint64_t info;
    oe_int64_t addend;
}
OE_Reloc;

OE_EXTERNC_END

#endif /* _OE_RELOC_H */
