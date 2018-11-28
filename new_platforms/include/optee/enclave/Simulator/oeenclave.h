/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_ENCLAVE_H
# error include <openenclave/enclave.h> instead of including oeenclave.h directly
#endif

#include "compiler.h"

/* Redefine APIs that are defined in Windows but not in OP-TEE.
 * This way, the "OP-TEE" calls will be mapped to oe_* and
 * not result in a duplicate definition.
 */
#include <stdlib.h>
#define atoi        oe_atoi
#define bsearch     oe_bsearch
#define strtol      oe_strtol
#define strtoul     oe_strtoul

#include <string.h>
#define strerror    oe_strerror
#define _stricmp    oe__stricmp
#define _strnicmp   oe__strnicmp
#define strncat     oe_strncat
#define strncpy     oe_strncpy
#define strncpy_s   oe_strncpy_s
#define strcpy_s    oe_strcpy_s
#define strrchr     oe_strrchr
#define strstr      oe_strstr

#include <ctype.h>
#define isalpha     oe_isalpha
#define isspace     oe_isspace
#define isupper     oe_isupper
#define tolower     oe_tolower
#define toupper     oe_toupper

#define HAVE_VSNPRINTF
#undef _CRT_FUNCTIONS_REQUIRED
#define _CRT_FUNCTIONS_REQUIRED 0
#define printf      oe_printf
#define vprintf     oe_vprintf
#define fprintf     oe_fprintf
#define snprintf    oe_snprintf

#define _INC_TIME_INL

#undef INVALID_HANDLE_VALUE
#undef errno

#include "..\..\..\oeenclave.h"
#include <unistd.h>

void* oe_memcpy(
    _Out_writes_bytes_(count) void* dest,
    _In_reads_bytes_(count) const void* src,
    _In_ size_t count);

void *oe_malloc(size_t size);

void oe_free(void *memblock); 

void* oe_realloc(  
    void *memblock,  
    size_t size);  

int snprintf(
    char *buffer,
    size_t count,
    const char *format,
    ...);
