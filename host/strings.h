#ifndef _OE_HOST_STRINGS_H
#define _OE_HOST_STRINGS_H

#include <stddef.h>

char* OE_Strdup(const char* str);

size_t OE_Strlcpy(char* dest, const char* src, size_t size);

size_t OE_Strlcat(char* dest, const char* src, size_t size);

#endif /* _OE_HOST_STRINGS_H */
