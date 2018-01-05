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

static OE_H_OnceType _enclave_once;
static OE_H_ThreadKey _enclave_key;

static void _CreateEnclaveKey(void)
{
    OE_H_ThreadKeyCreate(&_enclave_key);
}

void SetEnclave(OE_Enclave* enclave)
{
    OE_H_Once(&_enclave_once, _CreateEnclaveKey);
    OE_H_ThreadSetSpecific(_enclave_key, enclave);
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
    OE_H_Once(&_enclave_once, _CreateEnclaveKey);
    return (OE_Enclave*)OE_H_ThreadGetSpecific(_enclave_key);
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
