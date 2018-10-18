// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_PE_H
#define _OE_HOST_PE_H

#define FIELD_OFFSET(TYPE, Field) ((UINTN)(&(((TYPE*)0)->Field)))

typedef bool BOOL;
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint32_t UINT64;
typedef uint64_t UINTN;

#include "../3rdparty/gnu-efi/gnu-efi/gnu-efi-3.0/inc/x86_64/pe.h"

#endif /* _OE_HOST_PE_H */
