#ifndef _OE_HOST_FOPEN_H
#define _OE_HOST_FOPEN_H

#include <stdio.h>

int OE_Fopen(
    FILE** fp,
    const char* path,
    const char* mode);

#endif /* _OE_HOST_FOPEN_H */
