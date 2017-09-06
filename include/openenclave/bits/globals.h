#ifndef _OE_GLOBALS_H
#define _OE_GLOBALS_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

/* Enclave */
extern unsigned long long __oe_numPages;
extern unsigned long long __oe_virtualBaseAddr;
const void* __OE_GetEnclaveBase(void);
oe_size_t __OE_GetEnclaveSize(void);

/* Reloc */
extern unsigned long long __oe_baseRelocPage;
extern unsigned long long __oe_numRelocPages;
const void* __OE_GetRelocBase(void);
const void* __OE_GetRelocEnd(void);
const oe_size_t __OE_GetRelocSize(void);

/* Heap */
extern unsigned long long __oe_baseHeapPage;
extern unsigned long long __oe_numHeapPages;
const void* __OE_GetHeapBase(void);
const void* __OE_GetHeapEnd(void);
const oe_size_t __OE_GetHeapSize(void);

OE_EXTERNC_END

#endif /* _OE_ALLOC_H */
