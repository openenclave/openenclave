// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_GLOBALS_H
#define _OE_GLOBALS_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

/* Enclave */
extern unsigned long long __oe_numPages;
extern unsigned long long __oe_virtualBaseAddr;
const void* __oe_get_enclave_base(void);
size_t __oe_get_enclave_size(void);

/* Reloc */
extern unsigned long long __oe_baseRelocPage;
extern unsigned long long __oe_numRelocPages;
const void* __oe_get_reloc_base(void);
const void* __oe_get_reloc_end(void);
const size_t __oe_get_reloc_size(void);

/* ECall */
extern unsigned long long __oe_baseECallPage;
extern unsigned long long __oe_numECallPages;
const void* __oe_get_ecall_base(void);
const void* __oe_get_ecall_end(void);
const size_t __oe_get_ecall_size(void);

/* Heap */
extern unsigned long long __oe_baseHeapPage;
extern unsigned long long __oe_numHeapPages;
const void* __oe_get_heap_base(void);
const void* __oe_get_heap_end(void);
const size_t __oe_get_heap_size(void);

OE_EXTERNC_END

#endif /* _OE_ALLOC_H */
