// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_GLOBALS_H
#define _OE_GLOBALS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/* Enclave */
extern uint64_t __oe_numPages;
extern uint64_t __oe_virtualBaseAddr;
const void* __oe_get_enclave_base(void);
size_t __oe_get_enclave_size(void);

/* Reloc */
extern uint64_t __oe_baseRelocPage;
extern uint64_t __oe_numRelocPages;
const void* __oe_get_reloc_base(void);
const void* __oe_get_reloc_end(void);
const size_t __oe_get_reloc_size(void);

/* ECall */
extern uint64_t __oe_baseECallPage;
extern uint64_t __oe_numECallPages;
const void* __oe_get_ecall_base(void);
const void* __oe_get_ecall_end(void);
const size_t __oe_get_ecall_size(void);

/* Heap */
extern uint64_t __oe_baseHeapPage;
extern uint64_t __oe_numHeapPages;
const void* __oe_get_heap_base(void);
const void* __oe_get_heap_end(void);
const size_t __oe_get_heap_size(void);

OE_EXTERNC_END

#endif /* _OE_GLOBALS_H */
