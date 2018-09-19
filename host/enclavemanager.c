// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "enclave.h"
#include <assert.h>
#include <openenclave/host.h>
#include <openenclave/internal/queue.h>

static OE_LIST_HEAD(EnclaveListHead, _EnclaveEntry) g_enclave_list_head;
static oe_mutex g_enclave_list_lock = OE_H_MUTEX_INITIALIZER;

typedef struct _EnclaveEntry
{
    OE_LIST_ENTRY(_EnclaveEntry) next_entry;
    oe_enclave_t* enclave;
} EnclaveEntry;

/*
**==============================================================================
**
** _oe_push_enclave_instance()
**
**     Push the enclave to the head of the global enclave list.
**     Return 0 if success.
**
**==============================================================================
*/

uint32_t _oe_push_enclave_instance(oe_enclave_t* enclave)
{
    uint32_t ret = 1;
    bool locked = false;
    EnclaveEntry* newEntry = NULL;

    // Take the lock.
    if (oe_mutex_lock(&g_enclave_list_lock) != 0)
    {
        goto cleanup;
    }

    locked = true;

    // Return error if the enclave is already in global list.
    {
        EnclaveEntry* tmp;
        OE_LIST_FOREACH(tmp, &g_enclave_list_head, next_entry)
        {
            if (tmp->enclave == enclave)
            {
                goto cleanup;
            }
        }
    }

    // Allocate new entry.
    newEntry = (EnclaveEntry*)calloc(1, sizeof(EnclaveEntry));
    if (newEntry == NULL)
    {
        goto cleanup;
    }

    newEntry->enclave = enclave;

    // Insert to the beginning of the list.
    OE_LIST_INSERT_HEAD(&g_enclave_list_head, newEntry, next_entry);

    // Return success.
    ret = 0;

cleanup:
    if (locked)
    {
        // Release the lock if it is taken.
        if (oe_mutex_unlock(&g_enclave_list_lock) != 0)
        {
            abort();
        }
    }

    return ret;
}

/*
**==============================================================================
**
** _oe_remove_enclave_instance()
**
**     Remove the enclave from the global enclave list.
**     Return 0 if success.
**
**==============================================================================
*/

uint32_t _oe_remove_enclave_instance(oe_enclave_t* enclave)
{
    uint32_t ret = 1;
    bool locked = false;

    // Take the lock.
    if (oe_mutex_lock(&g_enclave_list_lock) != 0)
    {
        goto cleanup;
    }

    locked = true;

    // Enumerate the enclave list, remove the target entry if find it.
    {
        EnclaveEntry* tmp;
        OE_LIST_FOREACH(tmp, &g_enclave_list_head, next_entry)
        {
            if (tmp->enclave == enclave)
            {
                OE_LIST_REMOVE(tmp, next_entry);
                free(tmp);
                ret = 0;
                break;
            }
        }
    }

cleanup:
    if (locked)
    {
        // Release the lock if it is taken.
        if (oe_mutex_unlock(&g_enclave_list_lock) != 0)
        {
            abort();
        }
    }

    return ret;
}

/*
**==============================================================================
**
** _oe_query_enclave_instance()
**
**     Query the owner enclave for the given TCS.
**     Return the owner enclave if success, otherwise return NULL.
**
**==============================================================================
*/

oe_enclave_t* _oe_query_enclave_instance(void* tcs)
{
    oe_enclave_t* ret = NULL;
    bool locked = false;

    // Take the lock.
    if (oe_mutex_lock(&g_enclave_list_lock) != 0)
    {
        goto cleanup;
    }

    locked = true;

    // Enumerate the enclave list, find which enclave owns the TCS.
    {
        EnclaveEntry* tmp;
        OE_LIST_FOREACH(tmp, &g_enclave_list_head, next_entry)
        {
            oe_enclave_t* enclave = tmp->enclave;
            for (uint32_t i = 0; i < OE_COUNTOF(enclave->bindings); i++)
            {
                if (enclave->bindings[i].tcs == (uint64_t)tcs)
                {
                    ret = enclave;
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    if (locked)
    {
        // Release the lock if it is taken.
        if (oe_mutex_unlock(&g_enclave_list_lock) != 0)
        {
            abort();
        }
    }

    return ret;
}
