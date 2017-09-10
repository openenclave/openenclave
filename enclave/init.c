#include "init.h"
#include <openenclave/enclave.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/jump.h>
#include <openenclave/bits/fault.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/reloc.h>
#include <openenclave/bits/globals.h>
#include "asmdefs.h"
#include "td.h"

/*
**==============================================================================
**
** _ApplyRelocations()
**
**     Apply symbol relocations from the relocation pages, whose content
**     was copied from the ELF file during loading. These relocations are
**     included in the enclave signature (MRENCLAVE).
**
**==============================================================================
*/

static void _ApplyRelocations(void)
{
    const OE_Reloc* relocs = (const OE_Reloc*)__OE_GetRelocBase();
    size_t nrelocs = __OE_GetRelocSize() / sizeof(OE_Reloc);
    const uint8_t* baseaddr = (const uint8_t*)__OE_GetEnclaveBase();

    for (size_t i = 0; i < nrelocs; i++)
    {
        const OE_Reloc* p = &relocs[i];

        /* If zero-padded bytes reached */
        if (p->offset == 0)
            break;

        /* Compute address of reference to be relocated */
        uint64_t* dest = (uint64_t*)(baseaddr + p->offset);

        (void)dest;

        /* Relocate the reference */
        *dest = (uint64_t)(baseaddr + p->addend);
    }
}

/*
**==============================================================================
**
** _CheckMemoryBoundaries()
**
**     Check that the variables in globals.h are actually within the enclave.
**
**==============================================================================
*/

static void _CheckMemoryBoundaries(void)
{
    /* This is a tautology! */
    if (!OE_IsWithinEnclave(__OE_GetEnclaveBase(), __OE_GetEnclaveSize()))
        OE_Abort();

    if (!OE_IsWithinEnclave(__OE_GetRelocBase(), __OE_GetRelocSize()))
        OE_Abort();

    if (!OE_IsWithinEnclave(__OE_GetECallBase(), __OE_GetECallSize()))
        OE_Abort();

    if (!OE_IsWithinEnclave(__OE_GetHeapBase(), __OE_GetHeapSize()))
        OE_Abort();
}

/*
**==============================================================================
**
** OE_InitializeEnclave()
**
**     This function is called the first time the enclave is entered. It 
**     performs any necessary initialization, such as applying relocations.
**
**==============================================================================
*/

void OE_InitializeEnclave(TD* td)
{
OE_HostPrintf("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n");

    if (td->initialized == 0)
    {
        static OE_Spinlock _spin = OE_SPINLOCK_INITIALIZER;

        /* Prevent more than one thread from entering here */
        OE_SpinLock(&_spin);
        {
            if (td->initialized == 0)
            {
                /* Relocate symbols */
                _ApplyRelocations();

                /* Check that memory boundaries are within enclave */
                _CheckMemoryBoundaries();

                td->initialized = 1;
            }
        }
        OE_SpinUnlock(&_spin);
    }
}

/*
**==============================================================================
**
** __OE_Constructor()
**
**     This is the defaut OE_Constructor(). Since it is defined as a weak
**     reference, the enclave developer may override it with another
**     definition.
**
**==============================================================================
*/

void __OE_Constructor(void);

void __OE_Constructor(void)
{
}

OE_WEAK_ALIAS(__OE_Constructor, OE_Constructor);

/*
**==============================================================================
**
** __OE_Destructor()
**
**     This is the defaut OE_Destructor(). Since it is defined as a weak
**     reference, the enclave developer may override it with another
**     definition.
**
**==============================================================================
*/

void __OE_Destructor(void);

void __OE_Destructor(void)
{
}

OE_WEAK_ALIAS(__OE_Destructor, OE_Destructor);
