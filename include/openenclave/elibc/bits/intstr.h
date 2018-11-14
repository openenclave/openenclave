// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_INTSTR_H
#define _ELIBC_INTSTR_H

#include "common.h"

ELIBC_EXTERNC_BEGIN

typedef struct _elibc_intstr_buf
{
    char data[32];
} elibc_intstr_buf_t;

const char* elibc_uint64_to_hexstr(
    elibc_intstr_buf_t* buf,
    uint64_t x,
    size_t* size);

const char* elibc_uint64_to_octstr(
    elibc_intstr_buf_t* buf,
    uint64_t x,
    size_t* size);

const char* elibc_uint64_to_decstr(
    elibc_intstr_buf_t* buf,
    uint64_t x,
    size_t* size);

const char* elibc_int64_to_decstr(
    elibc_intstr_buf_t* buf,
    int64_t x,
    size_t* size);

ELIBC_EXTERNC_END

#endif /* _ELIBC_INTSTR_H */
