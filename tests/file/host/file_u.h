#ifndef _ENCIDL_FILE_U_H
#define _ENCIDL_FILE_U_H

#include <openenclave/host.h>

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

OE_EXTERNC FILE *Fopen(
    const char *filename,
    const char *modes);

OE_EXTERNC size_t Fread(
    void *ptr,
    size_t size,
    FILE *stream);

OE_EXTERNC int Fclose(
    FILE *stream);

/*
********************************************************************************
**
** Outbound calls
**
********************************************************************************
*/

OE_EXTERNC OE_Result TestReadFile(
    OE_Enclave* enclave,
    int *ret,
    const char *path,
    uint32_t *checksum);

#endif /* _ENCIDL_FILE_U_H */
