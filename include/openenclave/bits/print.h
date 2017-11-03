#ifndef _OE_PRINT_H
#define _OE_PRINT_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

int __OE_HostPuts(const char* str);

int __OE_HostPrint(int device, const char* str, size_t len);

int __OE_HostVprintf(const char* fmt, OE_va_list ap_);

int __OE_HostPutchar(int c);

OE_EXTERNC_END

#endif /* _OE_PRINT_H */
