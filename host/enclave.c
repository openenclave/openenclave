// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "enclave.h"
#include <assert.h>
#include <openenclave/host.h>

/* Get the event object from the enclave for the given TCS */
EnclaveEvent* GetEnclaveEvent(oe_enclave_t* enclave, uint64_t tcs)
{
    EnclaveEvent* event = NULL;

    if (!enclave)
        return NULL;

    oe_mutex_lock(&enclave->lock);
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
    oe_mutex_unlock(&enclave->lock);

    return event;
}
