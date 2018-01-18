#ifndef _OE_ASM_H
#define _OE_ASM_H

#include <stdlib.h>
#include <string.h>
#include <openenclave/defs.h>
#include <openenclave/types.h>

void OE_SetGSRegisterBase(const void *ptr);

void* OE_GetGSRegisterBase();

bool OE_TestGSRegisterBase(const void *ptr);

OE_EXTERNC_END

#endif /* _OE_ASM_H */
