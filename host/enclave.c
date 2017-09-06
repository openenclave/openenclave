#include <assert.h>
#include <openenclave/host.h>
#include "enclave.h"

/*
**==============================================================================
**
** SetEnclave()
**
**     Set enclave into thread-specific data.
**
**==============================================================================
*/

static OE_OnceType _once;
static OE_ThreadKey _key;

static void _SetTDInit(void)
{
    OE_ThreadKeyCreate(&_key, NULL);
}

void SetEnclave(OE_Enclave* enclave)
{
    OE_Once(&_once, _SetTDInit);
    OE_ThreadSetSpecific(_key, enclave);
}

/*
**==============================================================================
**
** GetEnclave()
**
**     Get enclave from thread-specific data.
**
**==============================================================================
*/

OE_Enclave* GetEnclave()
{
    OE_Once(&_once, _SetTDInit);
    return (OE_Enclave*)OE_ThreadGetSpecific(_key);
}

/*
**==============================================================================
**
** GetText()
**
**     Print the address where to load enclave symbols in GDB (add-symbol-file)
**
**==============================================================================
*/

void enc(void);

void enc(void)
{
    OE_Enclave* enclave = GetEnclave();

    if (enclave)
    {
#if 0
        OE_SHA256Str hash;
        OE_SHA256ToStr(&enclave->hash, &hash);
        printf("Hash: %s\n", hash.buf);
#endif
        printf("\n");
        printf("Path: %s\n", enclave->path);
        printf("Addr: 0x%lx\n", enclave->addr);
        printf("Size: %lu\n", enclave->size);
        printf("TCSs: %lu\n", enclave->num_tds);
        printf("Syms: add-symbol-file %s 0x%lx\n", enclave->path, 
            enclave->text);
        printf("\n");
    }
    else
    {
        printf("No enclave is active\n");
    }
}

/*
**==============================================================================
**
** GetEnclaveEvent()
**
**     Get the event object from the enclave for the given TCS
**
**==============================================================================
*/

uint32_t* GetEnclaveEvent(uint64_t tcs)
{
    OE_Enclave* enclave = GetEnclave();
    uint32_t* event = NULL;

    if (!enclave)
        return NULL;

    OE_SpinLock(&enclave->lock);
    {
        size_t i;

        for (i = 0; i < enclave->num_tds; i++)
        {
            ThreadData* td = &enclave->tds[i];

            if (td->tcs == tcs)
            {
                event = &td->event;
                break;
            }
        }
    }
    OE_SpinUnlock(&enclave->lock);

    return event;
}
