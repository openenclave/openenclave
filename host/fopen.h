// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_FOPEN_H
#define _OE_HOST_FOPEN_H

#include <stdio.h>

/* Open a file where 'path' and 'mode' have the same meaning as for
 * the standard fopen() function. The 'fp' parameter is set upon success.
 * Return 0 on success, -1 on failure.
 */
int oe_fopen(FILE** fp, const char* path, const char* mode);

#endif /* _OE_HOST_FOPEN_H */
