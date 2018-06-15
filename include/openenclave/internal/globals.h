// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_GLOBALS_H
#define _OE_GLOBALS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/* Enclave */
extern uint64_t __oe_num_pages;
extern uint64_t __oe_virtual_base_addr;
const void* __oe_get_enclave_base(void);
size_t __oe_get_enclave_size(void);

/* Reloc */
extern uint64_t __oe_base_reloc_page;
extern uint64_t __oe_num_reloc_pages;
const void* __oe_get_reloc_base(void);
const void* __oe_get_reloc_end(void);
const size_t __oe_get_reloc_size(void);

/* ECall */
extern uint64_t __oe_base_ecall_page;
extern uint64_t __oe_num_ecall_pages;
const void* __oe_get_ecall_base(void);
const void* __oe_get_ecall_end(void);
const size_t __oe_get_ecall_size(void);

/* Heap */
extern uint64_t __oe_base_heap_page;
extern uint64_t __oe_num_heap_pages;
const void* __oe_get_heap_base(void);
const void* __oe_get_heap_end(void);
const size_t __oe_get_heap_size(void);

OE_EXTERNC_END

#endif /* _OE_GLOBALS_H */
