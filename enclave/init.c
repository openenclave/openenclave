#include "init.h"
#include <setjmp.h>
#include <openenclave.h>
#include <oeinternal/sgxtypes.h>
#include <oeinternal/fault.h>
#include <oeinternal/calls.h>
#include <oeinternal/reloc.h>
#include <oeinternal/globals.h>
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
        abort();

    if (!OE_IsWithinEnclave(__OE_GetRelocBase(), __OE_GetRelocSize()))
        abort();

    if (!OE_IsWithinEnclave(__OE_GetHeapBase(), __OE_GetHeapSize()))
        abort();
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
    /* Prevent two threads from executing below */
    {
        static OE_Spinlock spin = OE_SPINLOCK_INITIALIZER;
        OE_SpinLock(&spin);

        if (td->initialized)
        {
            OE_SpinUnlock(&spin);
            return;
        }

        td->initialized = 1;
        OE_SpinUnlock(&spin);
    }

    /* Check that global variables (set by host) are really within enclave */
    _CheckMemoryBoundaries();

    /* Relocate symbols */
    _ApplyRelocations();
}
