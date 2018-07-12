// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVELIBC_STDINT_H
#define _OE_ENCLAVELIBC_STDINT_H

#include "bits/common.h"

#define OE_INT8_MIN (-1 - 0x7f)
#define OE_INT8_MAX (0x7f)
#define OE_UINT8_MAX (0xff)
#define OE_INT16_MIN (-1 - 0x7fff)
#define OE_INT16_MAX (0x7fff)
#define OE_UINT16_MAX (0xffff)
#define OE_INT32_MIN (-1 - 0x7fffffff)
#define OE_INT32_MAX (0x7fffffff)
#define OE_UINT32_MAX (0xffffffffu)
#define OE_INT64_MIN (-1 - 0x7fffffffffffffff)
#define OE_INT64_MAX (0x7fffffffffffffff)
#define OE_UINT64_MAX (0xffffffffffffffffu)
#define OE_SIZE_MAX OE_UINT64_MAX

#if defined(OE_ENCLAVELIBC_NEED_STDC_NAMES)

#define INT8_MIN OE_INT8_MIN
#define INT8_MAX OE_INT8_MAX
#define UINT8_MAX OE_UINT8_MAX
#define INT16_MIN OE_INT16_MIN
#define INT16_MAX OE_INT16_MAX
#define UINT16_MAX OE_UINT16_MAX
#define INT32_MIN OE_INT32_MIN
#define INT32_MAX OE_INT32_MAX
#define UINT32_MAX OE_UINT32_MAX
#define INT64_MIN OE_INT64_MIN
#define INT64_MAX OE_INT64_MAX
#define UINT64_MAX OE_UINT64_MAX
#define SIZE_MAX OE_SIZE_MAX

#endif /* defined(OE_ENCLAVELIBC_NEED_STDC_NAMES) */

#endif /* _OE_ENCLAVELIBC_STDINT_H */
