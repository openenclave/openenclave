// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "enclave.h"
#include <assert.h>
#include <openenclave/host.h>
#include <openenclave/oe_queue.h>

static OE_LIST_HEAD(EnclaveListHead, _EnclaveEntry) g_enclave_list_head;
static OE_H_Mutex g_enclave_list_lock = OE_H_MUTEX_INITIALIZER;

typedef struct _EnclaveEntry
{
    OE_LIST_ENTRY(_EnclaveEntry) next_entry;
    OE_Enclave* enclave;
} EnclaveEntry;

/*
**==============================================================================
**
** _OE_PushEnclaveInstance()
**
**     Push the enclave to the head of the global enclave list.
**     Return 0 if success.
**
**==============================================================================
*/

uint32_t _OE_PushEnclaveInstance(OE_Enclave* enclave)
{
    uint32_t ret = 1;
    bool locked = false;

    // Take the lock.
    if (OE_H_MutexLock(&g_enclave_list_lock) != 0)
    {
        goto cleanup;
    }

    locked = true;

    // Return error if the enclave is already in global list.
    EnclaveEntry* tmp;
    OE_LIST_FOREACH(tmp, &g_enclave_list_head, next_entry)
    {
        if (tmp->enclave == enclave)
        {
            goto cleanup;
        }
    }

    // Allocate new entry.
    EnclaveEntry* newEntry = (EnclaveEntry*)calloc(1, sizeof(EnclaveEntry));
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
        if (OE_H_MutexUnlock(&g_enclave_list_lock) != 0)
        {
            abort();
        }
    }

    return ret;
}

/*
**==============================================================================
**
** _OE_RemoveEnclaveInstance()
**
**     Remove the enclave from the global enclave list.
**     Return 0 if success.
**
**==============================================================================
*/

uint32_t _OE_RemoveEnclaveInstance(OE_Enclave* enclave)
{
    uint32_t ret = 1;
    bool locked = false;

    // Take the lock.
    if (OE_H_MutexLock(&g_enclave_list_lock) != 0)
    {
        goto cleanup;
    }

    locked = true;

    // Enumerate the enclave list, remove the target entry if find it.
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

cleanup:
    if (locked)
    {
        // Release the lock if it is taken.
        if (OE_H_MutexUnlock(&g_enclave_list_lock) != 0)
        {
            abort();
        }
    }

    return ret;
}

/*
**==============================================================================
**
** _OE_QueryEnclaveInstance()
**
**     Query the owner enclave for the given TCS.
**     Return the owner enclave if success, otherwise return NULL.
**
**==============================================================================
*/

OE_Enclave* _OE_QueryEnclaveInstance(void* tcs)
{
    OE_Enclave* ret = NULL;
    bool locked = false;

    // Take the lock.
    if (OE_H_MutexLock(&g_enclave_list_lock) != 0)
    {
        goto cleanup;
    }

    locked = true;

    // Enumerate the enclave list, find which enclave owns the TCS.
    EnclaveEntry* tmp;
    OE_LIST_FOREACH(tmp, &g_enclave_list_head, next_entry)
    {
        OE_Enclave* enclave = tmp->enclave;
        for (uint32_t i = 0; i < OE_COUNTOF(enclave->bindings); i++)
        {
            if (enclave->bindings[i].tcs == (uint64_t)tcs)
            {
                ret = enclave;
                goto cleanup;
            }
        }
    }

cleanup:
    if (locked)
    {
        // Release the lock if it is taken.
        if (OE_H_MutexUnlock(&g_enclave_list_lock) != 0)
        {
            abort();
        }
    }

    return ret;
}
