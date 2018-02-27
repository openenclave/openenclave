#ifndef _OE_ERROR_H
#define _OE_ERROR_H

#include <openenclave/defs.h>
#include <openenclave/types.h>
#include <stdio.h>

OE_EXTERNC_BEGIN

OE_PRINTF_FORMAT(3, 4)
void __OE_PutErr(const char* file, unsigned int line, const char* format, ...);

void OE_SetProgramName(const char* name);

#define OE_PutErr(...) __OE_PutErr(__FILE__, __LINE__, __VA_ARGS__)

OE_EXTERNC_END

#endif /* _OE_ERROR_H */
