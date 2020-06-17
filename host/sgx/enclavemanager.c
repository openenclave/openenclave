// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/host.h>
#include <openenclave/internal/queue.h>
#include <openenclave/internal/trace.h>
#include "enclave.h"

static OE_LIST_HEAD(EnclaveListHead, _enclave_entry) oe_enclave_list_head;
static oe_mutex oe_enclave_list_lock = OE_H_MUTEX_INITIALIZER;

typedef struct _enclave_entry
{
    OE_LIST_ENTRY(_enclave_entry) next_entry;
    oe_enclave_t* enclave;
} EnclaveEntry;

/*
**==============================================================================
**
** oe_push_enclave_instance()
**
**     Push the enclave to the head of the global enclave list.
**     Return 0 if success.
**
**==============================================================================
*/

uint32_t oe_push_enclave_instance(oe_enclave_t* enclave)
{
    uint32_t ret = 1;
    bool locked = false;
    EnclaveEntry* new_entry = NULL;

    // Take the lock.
    if (oe_mutex_lock(&oe_enclave_list_lock) != 0)
    {
        goto cleanup;
    }

    locked = true;

    // Return error if the enclave is already in global list.
    {
        EnclaveEntry* tmp;
        OE_LIST_FOREACH(tmp, &oe_enclave_list_head, next_entry)
        {
            if (tmp->enclave == enclave)
            {
                OE_TRACE_ERROR("The enclave is already in global list\n");
                goto cleanup;
            }
        }
    }

    // Allocate new entry.
    new_entry = (EnclaveEntry*)calloc(1, sizeof(EnclaveEntry));
    if (new_entry == NULL)
    {
        OE_TRACE_ERROR("calloc for EnclaveEntry failed\n");
        goto cleanup;
    }

    new_entry->enclave = enclave;

    // Insert to the beginning of the list.
    OE_LIST_INSERT_HEAD(&oe_enclave_list_head, new_entry, next_entry);

    // Return success.
    ret = 0;

cleanup:
    if (locked)
    {
        // Release the lock if it is taken.
        if (oe_mutex_unlock(&oe_enclave_list_lock) != 0)
        {
            abort();
        }
    }
    if (ret)
        OE_TRACE_ERROR("enclave=0x%x\n", enclave);

    return ret;
}

/*
**==============================================================================
**
** oe_remove_enclave_instance()
**
**     Remove the enclave from the global enclave list.
**     Return 0 if success.
**
**==============================================================================
*/

uint32_t oe_remove_enclave_instance(oe_enclave_t* enclave)
{
    uint32_t ret = 1;
    bool locked = false;

    // Take the lock.
    if (oe_mutex_lock(&oe_enclave_list_lock) != 0)
    {
        OE_TRACE_ERROR("oe_mutex_lock failed\n");
        goto cleanup;
    }

    locked = true;

    // Enumerate the enclave list, remove the target entry if find it.
    {
        EnclaveEntry* tmp;
        OE_LIST_FOREACH(tmp, &oe_enclave_list_head, next_entry)
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
        if (oe_mutex_unlock(&oe_enclave_list_lock) != 0)
        {
            OE_TRACE_ERROR("oe_mutex_unlock failed and calling abort...\n");
            abort();
        }
    }

    if (ret)
        OE_TRACE_ERROR("enclave=0x%x\n", enclave);

    return ret;
}

/*
**==============================================================================
**
** oe_query_enclave_instance()
**
**     Query the owner enclave for the given TCS.
**     Return the owner enclave if success, otherwise return NULL.
**
**==============================================================================
*/

oe_enclave_t* oe_query_enclave_instance(void* tcs)
{
    oe_enclave_t* ret = NULL;
    bool locked = false;

    // Take the lock.
    if (oe_mutex_lock(&oe_enclave_list_lock) != 0)
    {
        OE_TRACE_ERROR("oe_mutex_lock failed\n");
        goto cleanup;
    }

    locked = true;

    // Enumerate the enclave list, find which enclave owns the TCS.
    {
        EnclaveEntry* tmp;
        OE_LIST_FOREACH(tmp, &oe_enclave_list_head, next_entry)
        {
            oe_enclave_t* enclave = tmp->enclave;

            oe_mutex_lock(&enclave->lock);

            for (uint32_t i = 0; i < OE_COUNTOF(enclave->bindings); i++)
            {
                if (enclave->bindings[i].tcs == (uint64_t)tcs)
                {
                    ret = enclave;
                    break;
                }
            }

            oe_mutex_unlock(&enclave->lock);
        }
    }

cleanup:
    if (locked)
    {
        // Release the lock if it is taken.
        if (oe_mutex_unlock(&oe_enclave_list_lock) != 0)
        {
            OE_TRACE_ERROR("oe_mutex_unlock failed\n");
            abort();
        }
    }

    if (!ret)
        OE_TRACE_ERROR("tcs=0x%x\n", tcs);

    return ret;
}
