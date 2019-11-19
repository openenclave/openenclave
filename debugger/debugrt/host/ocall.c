// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/debugrt/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

uint64_t oe_ocall_info_list_tls_index;

//static oe_debug_ocall_info_t

/**
 * Notify debugrt prior to doing an ocall in the current thread.
 */
OE_DEBUGRT_EXPORT oe_result_t
oe_debug_notify_ocall_start(oe_debug_ocall_info_t* ocall_info)
{
    ocall_info->magic = OE_DEBUG_OCALL_MAGIC;
    ocall_info->version = 1;
    ocall_info->thread_id = (uint64_t)GetCurrentThreadId();

    /* Update the listof ocalls */
    oe_debug_ocall_info_t* head = 
        (oe_debug_ocall_info_t*) TlsGetValue((DWORD)oe_ocall_info_list_tls_index);
    ocall_info->next = head;
    TlsSetValue((DWORD)oe_ocall_info_list_tls_index, ocall_info);

    return OE_OK;
}


/**
 * Notify debugrt that the ocall in the current thread has completed.
 */
OE_DEBUGRT_EXPORT oe_result_t oe_debug_notify_ocall_end(void)
{
    /* Update the listof ocalls */
    oe_debug_ocall_info_t* head = 
        (oe_debug_ocall_info_t*) TlsGetValue((DWORD)oe_ocall_info_list_tls_index);
    
    if (head != NULL)
    {
        oe_debug_ocall_info_t* next = head->next;
        memset(head, 0, sizeof(*head));
        TlsSetValue((DWORD)oe_ocall_info_list_tls_index, next);
    }
    
    return OE_OK;
}


BOOL WINAPI DllMain (
    HINSTANCE const instance,  // handle to DLL module
    DWORD     const reason,    // reason for calling function
    LPVOID    const reserved)
{
    oe_ocall_info_list_tls_index = TlsAlloc();    
    if (oe_ocall_info_list_tls_index == TLS_OUT_OF_INDEXES)
        return FALSE;
    return TRUE;
}
