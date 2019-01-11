/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#define _NO_CRT_STDIO_INLINE
#include <stddef.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include <openenclave/enclave.h>
#include <openenclave/bits/stdio.h>
#include "tcps_string_t.h"
#ifdef OE_USE_OPTEE
#include <optee/string_optee_t.h>
#include <optee/ctype_optee_t.h>
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

int _strnicmp(const char *string1,
              const char *string2,
              size_t count)
{
    int cmp;

    for (size_t i = 0; i < count; i++)
    {
        int a = string1[i];
        int b = string2[i];
        if (!a && !b)
        {
            return 0; /* Equal. */
        }
        cmp = tolower(a) - tolower(b);
        if (cmp != 0)
        {
            return cmp; /* Not equal. */
        }
    }
    return 0; /* Equal. */
}

int _stricmp(const char *string1,
             const char *string2)
{
    int cmp;

    for (size_t i = 0; ; i++)
    {
        int a = string1[i];
        int b = string2[i];
        if (!a && !b)
        {
            return 0; /* Equal. */
        }
        cmp = tolower(a) - tolower(b);
        if (cmp != 0)
        {
            return cmp; /* Not equal. */
        }
    }
    return 0; /* Equal. */
}

int _vsnprintf(
    char *buffer,
    size_t count,
    const char *format,
    va_list argptr)
{
    // vsnprintf always writes a null terminator, even if it truncates the output.
    // It returns the number of characters that would be written, not counting the null character, if count were sufficiently large,
    // or -1 if an encoding error occurred.

    // _vsnprintf only writes a null terminator if there is room at the end.
    // It returns the number of characters actually written, or -1 if output has been truncated.

    int ret = vsnprintf(buffer, count, format, argptr);
    if ((count == 0) || ((size_t)ret > count - 1)) {
        // Output has been truncated.
        return -1;
    }
    return ret;
}

#ifdef OE_USE_OPTEE
errno_t strcpy_s(
    char* strDestination,
    size_t sizeDestination,
    const char *strSource)
{
    return strncpy_s(strDestination, sizeDestination, strSource, sizeDestination
);
}

#ifndef _WIN32
errno_t strcat_s(
    char* strDestination,
    size_t sizeDestination,
    const char *strSource)
{
    int len = strlen(strDestination);
    return strcpy_s(strDestination + len, sizeDestination - len, strSource);
}
#endif
#endif

#if defined(_DEBUG) || defined(OE_USE_OPTEE)
char *strcpy(
    char *strDestination,
    const char *strSource)
{
    const char *s;
    char *d = strDestination;
    for (s = strSource; *s; s++) {
        *d = *s;
        d++;
    }
    *d = 0;
    return strDestination;
}

char *strcat(
    char *strDestination,
    const char *strSource)
{
    strcpy(strDestination + strlen(strDestination), strSource);
    return strDestination;
}
#endif

#define _TRUNCATE ((size_t)-1) 

#ifndef _STRIZE  
#define _STRIZE(x)  _VAL(x)  
#endif  
#ifndef _VAL  
#define _VAL(x)     #x  
#endif 

#define CRT_CHK(_Expr) do { \
    if (!(_Expr)) \
    { \
        oe_assert(__FILE__ ":" _STRIZE(__LINE__) " " #_Expr); \
    } \
} while(0)

#ifdef OE_USE_OPTEE
errno_t strncpy_s(
    char *Dest,
    size_t SizeInBytes,
    const char *Src,
    size_t MaxCount)
{
    size_t  len;  
    errno_t res = 0;  
  
    //  
    // If parameters are invalid, CRT_CHK does not return. So we do not  
    // explicitly zero Dest[0] if Src==NULL or an overflow happens.  
    //  
    CRT_CHK(Dest != NULL && Src != NULL && SizeInBytes != 0);  
  
    len = strnlen(Src, MaxCount);  
  
    if (MaxCount == _TRUNCATE)  
    {  
        if (len >= SizeInBytes)  
        {  
            len = SizeInBytes - 1;  
            res = STRUNCATE;  
        }  
    }  
    else  
    {  
        CRT_CHK(len < SizeInBytes);  
    }  
  
    memcpy(Dest, Src, len);  
    Dest[len] = 0;  
  
    return res;
}
#endif

errno_t strncat_s(
    char *strDest,
    size_t numberOfElements,
    const char *strSource,
    size_t count)
{
    size_t len = strlen(strDest);
    errno_t err = strncpy_s(strDest + len, numberOfElements - len, strSource, count);
    return err;
}

int 
ConvertStringToIPv4Integers(
    const char *addressString, 
    const char *addressSscanfFormat, 
    int        *addressByte0,
    int        *addressByte1,
    int        *addressByte2, 
    int        *addressByte3)
{
    const char *currentPart;
    const char *p;
    int parts = 0;
    int addressByteValues[4] = {0};

    Tcps_Trace(Tcps_TraceLevelDebug, "addressString = %s", addressString);

    /*
     * This function gets called just from openssl's ipv4_from_asc(),
     * using the following sscanf format string.
     */
    oe_assert(strcmp(addressSscanfFormat, "%d.%d.%d.%d") == 0);

    /* Implement inet_addr for SGX/OPTEE */
    for (currentPart = p = addressString; ; p++) {
        if (*p != 0 && *p != '.') {
            /* Find the next '.' character */
            continue;
        }

        addressByteValues[parts] = atoi(currentPart);
        parts++;

        if ((parts == ARRAY_SIZE(addressByteValues)) || (*p == 0)) {
            break;
        }

        currentPart = p + 1;
    }

    if (parts == 4) {
        *addressByte0 = addressByteValues[0];
        *addressByte1 = addressByteValues[1];
        *addressByte2 = addressByteValues[2];
        *addressByte3 = addressByteValues[3];
        Tcps_Trace(
            Tcps_TraceLevelDebug, 
            "returning %u %u %u %u", 
            *addressByte0, 
            *addressByte1, 
            *addressByte2, 
            *addressByte3);
    } else {
        Tcps_Trace(Tcps_TraceLevelError, "read just %u byte values from string %s", parts, addressString);
        parts = 0;
    }

    return parts;
}
