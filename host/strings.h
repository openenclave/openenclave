#ifndef _OE_HOST_STRINGS_H
#define _OE_HOST_STRINGS_H

#include <stddef.h>

char* Strdup(
    const char* str);

size_t Strlcpy(
    char* dest, 
    const char* src, 
    size_t size);

size_t Strlcat(
    char* dest, 
    const char* src, 
    size_t size);

#endif /* _OE_HOST_STRINGS_H */
