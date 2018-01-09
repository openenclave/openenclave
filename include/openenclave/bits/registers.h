#ifndef _OE_ASM_H
#define _OE_ASM_H

#include <stdlib.h>
#include <string.h>
#include <openenclave/defs.h>
#include <openenclave/types.h>

int OE_SetGSRegisterBase(const void *ptr);

int OE_GetGSRegisterBase(const void **ptr);

OE_EXTERNC_END

#endif /* _OE_ASM_H */
