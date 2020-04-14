// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/netdb.h>

typedef struct _error_info
{
    int errnum;
    const char* message;
} error_info_t;

// The following messages are copied from
// ../../3rdparty/musl/musl/src/network/gai_strerror.c
//
// Unlike MUSL's implementation of strerror() which puts all strings
// in a header file we can include, MUSL's implementation of gai_strerror()
// instead puts the strings into the .c file itself along with code we
// don't want.  As such, we have to copy the strings into this file rather
// than being able to include them from MUSL.
static error_info_t _errors[] = {
    {OE_EAI_BADFLAGS, "Invalid flags"},
    {OE_EAI_NONAME, "Name does not resolve"},
    {OE_EAI_AGAIN, "Try again"},
    {OE_EAI_FAIL, "Non-recoverable error"},
    {OE_EAI_NODATA, "Unknown error"},
    {OE_EAI_FAMILY, "Unrecognized address family or invalid length"},
    {OE_EAI_SOCKTYPE, "Unrecognized socket type"},
    {OE_EAI_SERVICE, "Unrecognized service"},
    {OE_EAI_ADDRFAMILY, "Unknown error"},
    {OE_EAI_MEMORY, "Out of memory"},
    {OE_EAI_SYSTEM, "System error"},
    {OE_EAI_OVERFLOW, "Overflow"},
};

static size_t _num_errors = sizeof(_errors) / sizeof(_errors[0]);

static const char _unknown[] = "Unknown error";

const char* oe_gai_strerror(int errnum)
{
    for (size_t i = 0; i < _num_errors; i++)
    {
        if (_errors[i].errnum == errnum)
            return (char*)_errors[i].message;
    }

    return (char*)_unknown;
}
