#ifndef _ENCIDL_FILE_T_H
#define _ENCIDL_FILE_T_H

#include <openenclave/enclave.h>

#include "../types.h"

/*
********************************************************************************
**
** Structure definitions
**
********************************************************************************
*/

/*
********************************************************************************
**
** Inbound calls
**
********************************************************************************
*/

OE_EXTERNC int TestReadFile(
    const char *path,
    oe_uint32_t *checksum);

/*
********************************************************************************
**
** Outbound calls
**
********************************************************************************
*/

OE_EXTERNC OE_Result Fopen(
    FILE **ret,
    const char *filename,
    const char *modes);

OE_EXTERNC OE_Result Fread(
    oe_size_t *ret,
    void *ptr,
    oe_size_t size,
    FILE *stream);

OE_EXTERNC OE_Result Fclose(
    int *ret,
    FILE *stream);

#endif /* _ENCIDL_FILE_T_H */
