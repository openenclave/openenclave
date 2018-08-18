// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "enclave.h"
#include <assert.h>
#include <openenclave/host.h>
#include <openenclave/internal/raise.h>

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

typedef struct _enclave_node enclave_node_t;

/* Node on an enclave instance stack */
struct _enclave_node
{
    oe_enclave_t* enclave;
    enclave_node_t* next;
};

static oe_once_type _once;
static oe_thread_key _key;

static void _create_key(void)
{
    oe_thread_key_create(&_key);
}

oe_result_t oe_push_enclave(oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    enclave_node_t* node = NULL;

    if (!enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize the stack of enclave nodes the first time */
    oe_once(&_once, _create_key);

    /* Allocate the stack node */
    if (!(node = (enclave_node_t*)malloc(sizeof(enclave_node_t))))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Push node onto TLS stack of enclave nodes */
    {
        node->enclave = enclave;
        node->next = (enclave_node_t*)oe_thread_getspecific(_key);

        if (oe_thread_setspecific(_key, node) != 0)
            OE_RAISE(OE_FAILURE);

        node = NULL;
    }

    result = OE_OK;

done:

    if (node)
        free(node);

    return result;
}

oe_result_t oe_pop_enclave(oe_enclave_t** enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    enclave_node_t* node = NULL;

    if (enclave)
        *enclave = NULL;

    /* Initialize the stack of enclave nodes the first time */
    oe_once(&_once, _create_key);

    /* Get the top node on the stack if any */
    if ((node = (enclave_node_t*)oe_thread_getspecific(_key)))
    {
        /* Pop the top node from stack */
        if (oe_thread_setspecific(_key, node->next) != 0)
            OE_RAISE(OE_FAILURE);

        if (enclave)
            *enclave = node->enclave;
    }

    result = OE_OK;

done:

    if (node)
        free(node);

    return result;
}

oe_enclave_t* oe_get_ocall_enclave(void)
{
    const enclave_node_t* node;

    /* Get the next node on the stack if any */
    if (!(node = (enclave_node_t*)oe_thread_getspecific(_key)))
        return NULL;

    return node->enclave;
}
