// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file security.h
 *
 * This file defines the security-related primitives for an enclave.
 *
 */

#ifndef _OE_BITS_SECURITY_H
#define _OE_BITS_SECURITY_H

#if __x86_64__ || _M_X64
#include "sgx/writebarrier.h"
#elif defined(__aarch64__)
/* Alias oe_memcpy_with_barrier with regular mempcy (required by
 * oeedger8r-generated code) */
#define oe_memcpy_with_barrier memcpy
#endif

#endif
