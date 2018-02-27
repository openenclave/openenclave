#include "enclave.h"
#include <assert.h>
#include <openenclave/host.h>

/*
**==============================================================================
**
** GetText()
**
**     Print the address where to load enclave symbols in GDB (add-symbol-file)
**
**==============================================================================
*/

#if 0
/* ATTN: should this be removed: disabled after debugger work. It is useful
 * for debugging simulated mode.
 */
void enc(void);

void enc(void)
{
    OE_Enclave* enclave = GetEnclave();

    if (enclave)
    {
        OE_SHA256Str hash;
        OE_SHA256ToStr(&enclave->hash, &hash);
        printf("Hash: %s\n", hash.buf);
        printf("\n");
        printf("Path: %s\n", enclave->path);
        printf("Addr: 0x" OE_I64X_F "\n", enclave->addr);
        printf("Size: " OE_I64U_F "\n", enclave->size);
        printf("TCSs: %zu\n", enclave->num_bindings);
        printf("Syms: add-symbol-file %s 0x" OE_I64X_F "\n", enclave->path,
            enclave->text);
        printf("\n");
    }
    else
    {
        printf("No enclave is active\n");
    }
}
#endif

/*
**==============================================================================
**
** GetEnclaveEvent()
**
**     Get the event object from the enclave for the given TCS
**
**==============================================================================
*/

EnclaveEvent* GetEnclaveEvent(OE_Enclave* enclave, uint64_t tcs)
{
    EnclaveEvent* event = NULL;

    if (!enclave)
        return NULL;

    OE_H_MutexLock(&enclave->lock);
    {
        size_t i;

        for (i = 0; i < enclave->num_bindings; i++)
        {
            ThreadBinding* binding = &enclave->bindings[i];

            if (binding->tcs == tcs)
            {
                event = &binding->event;
                break;
            }
        }
    }
    OE_H_MutexUnlock(&enclave->lock);

    return event;
}
