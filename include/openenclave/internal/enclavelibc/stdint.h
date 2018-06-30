// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVELIBC_STDINT_H
#define _OE_ENCLAVELIBC_STDINT_H

#include "bits/common.h"

#define INT8_MIN (-1-0x7f)
#define INT8_MAX (0x7f)
#define UINT8_MAX (0xff)

#define INT16_MIN (-1-0x7fff)
#define INT16_MAX (0x7fff)
#define UINT16_MAX (0xffff)

#define INT32_MIN (-1-0x7fffffff)
#define INT32_MAX (0x7fffffff)
#define UINT32_MAX (0xffffffffu)

#define INT64_MIN (-1-0x7fffffffffffffff)
#define INT64_MAX (0x7fffffffffffffff)
#define UINT64_MAX (0xffffffffffffffffu)

#define SIZE_MAX UINT64_MAX

#endif /* _OE_ENCLAVELIBC_STDINT_H */
