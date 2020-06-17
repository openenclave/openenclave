// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_STRTOUL_H
#define _OE_BITS_STRTOUL_H

OE_INLINE
unsigned long int strtoul(const char* nptr, char** endptr, int base)
{
    return oe_strtoul(nptr, endptr, base);
}

#endif /* _OE_BITS_STRTOUL_H */
