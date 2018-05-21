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
const void* __OE_GetEnclaveBase(void);
size_t __OE_GetEnclaveSize(void);

/* Reloc */
extern unsigned long long __oe_baseRelocPage;
extern unsigned long long __oe_numRelocPages;
const void* __OE_GetRelocBase(void);
const void* __OE_GetRelocEnd(void);
size_t __OE_GetRelocSize(void);

/* ECall */
extern unsigned long long __oe_baseECallPage;
extern unsigned long long __oe_numECallPages;
const void* __OE_GetECallBase(void);
const void* __OE_GetECallEnd(void);
size_t __OE_GetECallSize(void);

/* Heap */
extern unsigned long long __oe_baseHeapPage;
extern unsigned long long __oe_numHeapPages;
const void* __OE_GetHeapBase(void);
const void* __OE_GetHeapEnd(void);
size_t __OE_GetHeapSize(void);

OE_EXTERNC_END

#endif /* _OE_ALLOC_H */
