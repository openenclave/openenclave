// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_CONSTANTS_X64_H
#define _OE_INTERNAL_CONSTANTS_X64_H

#include <openenclave/internal/defs.h>

//
// Contains AMD64 architecture constants.
//

//
// SGX hardware constant definitions.
//

#define SGX_SSA_RSP_OFFSET 0XF68

//
// Open Enclave layout constant definitions.
//

#define OE_SSA_FROM_TCS_BYTE_OFFSET OE_PAGE_SIZE
#define OE_DEFAULT_SSA_FRAME_SIZE 0x1
#define OE_SGX_GPR_BYTE_SIZE 0xb8
#define OE_SGX_TCS_HEADER_BYTE_SIZE 0x48

//
// oe_context_t Structure size and offset definitions.
//

#define OE_CONTEXT_SIZE 0X2A0

#define OE_CONTEXT_FLAGS 0x00
#define OE_CONTEXT_RAX 0x08
#define OE_CONTEXT_RBX 0x10
#define OE_CONTEXT_RCX 0x18
#define OE_CONTEXT_RDX 0x20
#define OE_CONTEXT_RBP 0x28
#define OE_CONTEXT_RSP 0x30
#define OE_CONTEXT_RDI 0x38
#define OE_CONTEXT_RSI 0x40
#define OE_CONTEXT_R8 0x48
#define OE_CONTEXT_R9 0x50
#define OE_CONTEXT_R10 0x58
#define OE_CONTEXT_R11 0x60
#define OE_CONTEXT_R12 0x68
#define OE_CONTEXT_R13 0x70
#define OE_CONTEXT_R14 0x78
#define OE_CONTEXT_R15 0x80
#define OE_CONTEXT_RIP 0x88
#define OE_CONTEXT_MXCSR 0x90
#define OE_CONTEXT_FLOAT 0xA0

//
// XSTATE constants.
//

#define XSAVE_ALIGNMENT 0x40
#define LEGACY_XSAVE_AREA 0X200
#define XSAVE_HEADER_LENGTH 0X40
#define MINIMAL_XSTATE_AREA_LENGTH (LEGACY_XSAVE_AREA + XSAVE_HEADER_LENGTH)

//
//  AMD64 ABI related constants.
//

//  AMD64 ABI needs a 128 bytes red zone.
#define ABI_REDZONE_BYTE_SIZE 0x80

#endif /* _OE_INTERNAL_CONSTANTS_X64_H */
