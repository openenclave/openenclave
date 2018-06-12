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
const void* __OE_GetEnclaveBase(void);
size_t __OE_GetEnclaveSize(void);

/* Reloc */
extern uint64_t __oe_baseRelocPage;
extern uint64_t __oe_numRelocPages;
const void* __OE_GetRelocBase(void);
const void* __OE_GetRelocEnd(void);
const size_t __OE_GetRelocSize(void);

/* ECall */
extern uint64_t __oe_baseECallPage;
extern uint64_t __oe_numECallPages;
const void* __OE_GetECallBase(void);
const void* __OE_GetECallEnd(void);
const size_t __OE_GetECallSize(void);

/* Heap */
extern uint64_t __oe_baseHeapPage;
extern uint64_t __oe_numHeapPages;
const void* __OE_GetHeapBase(void);
const void* __OE_GetHeapEnd(void);
const size_t __OE_GetHeapSize(void);

OE_EXTERNC_END

#endif /* _OE_GLOBALS_H */
