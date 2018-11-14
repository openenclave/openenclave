// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_STDINT_H
#define _ELIBC_STDINT_H

#include "bits/common.h"

#define ELIBC_INT8_MIN (-1 - 0x7f)
#define ELIBC_INT8_MAX (0x7f)
#define ELIBC_UINT8_MAX (0xff)
#define ELIBC_INT16_MIN (-1 - 0x7fff)
#define ELIBC_INT16_MAX (0x7fff)
#define ELIBC_UINT16_MAX (0xffff)
#define ELIBC_INT32_MIN (-1 - 0x7fffffff)
#define ELIBC_INT32_MAX (0x7fffffff)
#define ELIBC_UINT32_MAX (0xffffffffu)
#define ELIBC_INT64_MIN (-1 - 0x7fffffffffffffff)
#define ELIBC_INT64_MAX (0x7fffffffffffffff)
#define ELIBC_UINT64_MAX (0xffffffffffffffffu)
#define ELIBC_SIZE_MAX ELIBC_UINT64_MAX

#if defined(ELIBC_NEED_STDC_NAMES)

#define INT8_MIN ELIBC_INT8_MIN
#define INT8_MAX ELIBC_INT8_MAX
#define UINT8_MAX ELIBC_UINT8_MAX
#define INT16_MIN ELIBC_INT16_MIN
#define INT16_MAX ELIBC_INT16_MAX
#define UINT16_MAX ELIBC_UINT16_MAX
#define INT32_MIN ELIBC_INT32_MIN
#define INT32_MAX ELIBC_INT32_MAX
#define UINT32_MAX ELIBC_UINT32_MAX
#define INT64_MIN ELIBC_INT64_MIN
#define INT64_MAX ELIBC_INT64_MAX
#define UINT64_MAX ELIBC_UINT64_MAX
#define SIZE_MAX ELIBC_SIZE_MAX

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

#endif /* _ELIBC_STDINT_H */
