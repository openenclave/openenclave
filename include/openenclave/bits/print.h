#ifndef _OE_PRINT_H
#define _OE_PRINT_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

int __OE_HostPuts(const char* str);

int __OE_HostPrint(const char* str);

int __OE_HostVprintf(const char* fmt, OE_va_list ap_);

int __OE_HostPutchar(int c);

#endif /* _OE_PRINT_H */
