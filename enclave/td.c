#include <openenclave.h>
#include <oeinternal/sgxtypes.h>
#include <oeinternal/fault.h>
#include "td.h"
#include "asmdefs.h"

OE_STATIC_ASSERT(offsetof(TD, magic) == TD_magic);
OE_STATIC_ASSERT(offsetof(TD, depth) == TD_depth);
OE_STATIC_ASSERT(offsetof(TD, initialized) == TD_initialized);
OE_STATIC_ASSERT(offsetof(TD, host_rcx) == TD_host_rcx);
OE_STATIC_ASSERT(offsetof(TD, host_rdx) == TD_host_rdx);
OE_STATIC_ASSERT(offsetof(TD, host_r8) == TD_host_r8);
OE_STATIC_ASSERT(offsetof(TD, host_r9) == TD_host_r9);
OE_STATIC_ASSERT(offsetof(TD, host_r10) == TD_host_r10);
OE_STATIC_ASSERT(offsetof(TD, host_r11) == TD_host_r11);
OE_STATIC_ASSERT(offsetof(TD, host_r12) == TD_host_r12);
OE_STATIC_ASSERT(offsetof(TD, host_r13) == TD_host_r13);
OE_STATIC_ASSERT(offsetof(TD, host_r14) == TD_host_r14);
OE_STATIC_ASSERT(offsetof(TD, host_r15) == TD_host_r15);
OE_STATIC_ASSERT(offsetof(TD, host_rsp) == TD_host_rsp);
OE_STATIC_ASSERT(offsetof(TD, host_rbp) == TD_host_rbp);
OE_STATIC_ASSERT(offsetof(TD, oret_func) == TD_oret_func);
OE_STATIC_ASSERT(offsetof(TD, oret_arg) == TD_oret_arg);
OE_STATIC_ASSERT(offsetof(TD, callsites) == TD_callsites);
OE_STATIC_ASSERT(offsetof(TD, simulate) == TD_simulate);

/*
**==============================================================================
**
** OE_GetThreadData()
**
**     Returns a pointer to the thread data structure for the current thread.
**     This structure resides in the GS segment. Offset zero of this segment
**     contains the OE_ThreadData.self_addr field (a back pointer to the 
**     structure itself). This field is zero until the structure is initialized
**     by __OE_HandleEnter (which happens immediately an EENTER).
**
**==============================================================================
*/

OE_ThreadData* OE_GetThreadData()
{
    OE_ThreadData* td = NULL;

    asm volatile(
        "mov %%gs:0, %%rax\n\t"
        "mov %%rax, %0\n\t"
        : 
        "=a"(td));

    return td;
}

/*
**==============================================================================
**
** TD_PushCallsite()
**
**     Insert the Callsite structure for the current ECALL at the
**     front of the TD.callsites list.
**
**==============================================================================
*/

void TD_PushCallsite(TD* td, Callsite* callsite)
{
    callsite->next = td->callsites;
    td->callsites = callsite;
    td->depth++;
}

/*
**==============================================================================
**
** TD_PopCallsite()
**
**     Remove the Callsite structure that is at the head of the
**     TD.callsites list.
**
**==============================================================================
*/

void TD_PopCallsite(TD* td)
{
    if (!td->callsites)
        abort();

    td->callsites = td->callsites->next;

    if (--td->depth == 0)
        TD_Clear(td);
}

/*
**==============================================================================
**
** TD_FromTCS()
**
**     This function calculates the address of the TD (thread data structure)
**     relative to the TCS (Thread Control Structure) page. The TD resides in
**     a page pointed to by the GS (segment register). This page occurs 4 pages
**     after the TCS page. The layout is as follows:
**
**         +--------------------------+
**         | TCS Page                 |
**         +--------------------------+
**         | SSA (State Save Area) 0  |
**         +--------------------------+
**         | SSA (State Save Area) 1  |
**         +--------------------------+
**         | Guard Page               |
**         +--------------------------+
**         | GS Segment (contains TD) |
**         +--------------------------+
**
**     This layout is determined by the enclave builder. See:
**
**         ../host/build.c (_AddControlPages)
**
**     The GS segment register is set by the EENTER instruction and the TD
**     page is zero filled upon initial enclave entry. Software sets the
**     contents of the TD when it first determines that TD.self_addr is zero.
**
**==============================================================================
*/

TD* TD_FromTCS(void* tcs)
{
    return (TD*)((uint8_t*)tcs + (4 * OE_PAGE_SIZE));
}

/*
**==============================================================================
**
** TD_ToTCS()
**
**     Compute a TCS pointer from a TD.
**
**==============================================================================
*/

void* TD_ToTCS(const TD* td)
{
    return (uint8_t*)td - (4 * OE_PAGE_SIZE);
}

/*
**==============================================================================
**
** TD_Get()
**
**     Gets a pointer to the thread data structure from the GS segment.
**
**==============================================================================
*/

TD* TD_Get()
{
    OE_ThreadData* td = OE_GetThreadData();
    return (TD*)td;
}

/*
**==============================================================================
**
** TD_Initialized()
**
**     Returns TRUE if this thread data structure (TD) is initialized. An
**     initialized TD meets the following conditions:
**
**         (1) td is not null
**         (2) td->base.self_addr == td
**         (3) td->magic == TD_MAGIC
**
**==============================================================================
*/

bool TD_Initialized(TD* td)
{
    if (td && td->magic == TD_MAGIC && td->base.self_addr == (uint64_t)td)
        return true;

    return false;
}

/*
**==============================================================================
**
** TD_Init()
**
**     Initialize the thread data structure (TD) if not already initialized.
**     The TD resides in the GS segment and is located relative to the TCS. 
**     Refer to the following layout.
**
**         +-------------------------+
**         | Guard Page              |
**         +-------------------------+
**         | Stack pages             |
**         +-------------------------+
**         | Guard Page              |
**         +-------------------------+
**         | TCS Page                |
**         +-------------------------+
**         | SSA (State Save Area) 0 |
**         +-------------------------+
**         | SSA (State Save Area) 1 |
**         +-------------------------+
**         | Guard Page              |
**         +-------------------------+
**         | GS page (contains TD)   |
**         +-------------------------+
**
**     Note: the host register fields are pre-initialized by OE_Main:
**
**==============================================================================
*/

void TD_Init(TD* td)
{
    /* If not already initialized */
    if (!TD_Initialized(td))
    {
        /* TD.hostsp, TD.hostbp, and TD.retaddr already set by OE_Main() */

        /* Clear base structure */
        memset(&td->base, 0, sizeof(td->base));

        /* Set pointer to self */
        td->base.self_addr = (uint64_t)td;

        /* Set the magic number */
        td->magic = TD_MAGIC;

        /* Set the ECALL depth to zero */
        td->depth = 0;

        /* List of callsites is initially empty */
        td->callsites = NULL;
    }
}

/*
**==============================================================================
**
** TD_Clear()
**
**     Clear the TD. This is called when the ECALL depth falls to zero
**     in TD_PopCallsite().
**
**==============================================================================
*/

void TD_Clear(TD* td)
{
    /* Should not be called unless callsite list is empty */
    if (td->depth != 0 || td->callsites)
        abort();

    /* Clear base structure */
    memset(&td->base, 0, sizeof(td->base));

    /* Clear the self pointer */
    td->base.self_addr = 0;

    /* Clear the magic number */
    td->magic = TD_MAGIC;

    /* Never clear TD.initialized nor host registers */
}
