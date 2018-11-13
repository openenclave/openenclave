/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_ENCLAVE_H
# include <openenclave/enclave.h>
#endif

#include <string.h>
#include "tcps_stdio_t.h"

#ifndef ERRNO
typedef int errno_t;
#define ERRNO
#endif

#ifndef _INC_STRING
/* Only include these if string.h didn't include them. */

errno_t strcpy_s(
    char* strDestination,
    size_t sizeDestination,
    const char *strSource);

int _strnicmp(const char *string1,
    const char *string2,
    size_t count);

#define strcasecmp _stricmp
#define strncasecmp _strnicmp

int _stricmp(const char *string1,
    const char *string2);

errno_t strncpy_s(
    char *strDest,
    size_t numberOfElements,
    const char *strSource,
    size_t count);

errno_t strncat_s(
    char *strDest,
    size_t numberOfElements,
    const char *strSource,
    size_t count);

char *strcat(
    char *strDestination,
    const char *strSource);

char* strcpy(
    char* strDestination,
    const char* strSource);

errno_t strcat_s(
    char* strDestination,
    size_t sizeDestination,
    const char* strSource);
#endif /* !_INC_STRING */

int _vsnprintf(
    char* buffer,
    size_t count,
    const char* format,
    va_list argptr)
#ifdef OE_USE_OPTEE
    __attribute__((format(printf, 3, 0)))
#endif
    ;

/* sscanf is used just by openssl's ipv4_from_asc() */
int 
ConvertStringToIPv4Integers(
    const char *addressString, 
    const char *addressSscanfFormat, 
    int        *addressByte0, 
    int        *addressByte1,
    int        *addressByte2, 
    int        *addressByte3
);

#define sscanf(addressString, addressSscanfFormat, addressByte0, addressByte1, addressByte2, addressByte3)  \
    ConvertStringToIPv4Integers(addressString, addressSscanfFormat, addressByte0, addressByte1, addressByte2, addressByte3)

#ifdef OE_USE_OPTEE
# include <optee/string_optee_t.h>
#endif
