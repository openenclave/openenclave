/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef TRUSTED_CODE
# error TCPS-SDK\Inc\optee\Trusted headers should only be included with TRUSTED_CODE
#endif

#include "compiler.h"

/* Redefine APIs that are defined in Windows but not in OP-TEE.
 * This way, the "OP-TEE" calls will be mapped to Tcps_* and
 * not result in a duplicate definition.
 */
#include <stdlib.h>
#define atoi        Tcps_atoi
#define bsearch     Tcps_bsearch
#define strtol      Tcps_strtol
#define strtoul     Tcps_strtoul

#include <string.h>
#define strerror    Tcps_strerror
#define _stricmp    Tcps__stricmp
#define _strnicmp   Tcps__strnicmp
#define strncat     Tcps_strncat
#define strncpy     Tcps_strncpy
#define strncpy_s   Tcps_strncpy_s
#define strcpy_s    Tcps_strcpy_s
#define strrchr     Tcps_strrchr
#define strstr      Tcps_strstr

#include <ctype.h>
#define isalpha     Tcps_isalpha
#define isspace     Tcps_isspace
#define isupper     Tcps_isupper
#define tolower     Tcps_tolower
#define toupper     Tcps_toupper

#define HAVE_VSNPRINTF
#undef _CRT_FUNCTIONS_REQUIRED
#define _CRT_FUNCTIONS_REQUIRED 0
#define printf      Tcps_printf
#define vprintf     Tcps_vprintf
#define fprintf     Tcps_fprintf
#define snprintf    Tcps_snprintf

#define _INC_TIME_INL

#undef INVALID_HANDLE_VALUE
#undef errno

#include "..\..\..\tcps_t.h"
#include <unistd.h>

void* Tcps_memcpy(
    _Out_writes_bytes_(count) void* dest,
    _In_reads_bytes_(count) const void* src,
    _In_ size_t count);

void *Tcps_malloc(size_t size);

void Tcps_free(void *memblock); 

void* Tcps_realloc(  
    void *memblock,  
    size_t size);  

int snprintf(
    char *buffer,
    size_t count,
    const char *format,
    ...);
