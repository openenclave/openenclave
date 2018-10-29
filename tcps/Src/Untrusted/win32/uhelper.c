/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <time.h>
#include <windows.h> // for LARGE_INTEGER
#include <openenclave/host.h>
#include "../TcpsCalls_u.h"

#define MIN(a,b) (((a) < b) ? (a) : (b))

/* Time-related APIs */

QueryPerformanceCounter_Result ocall_QueryPerformanceCounter(void)
{
    QueryPerformanceCounter_Result result;

    if (!QueryPerformanceCounter((LARGE_INTEGER*)&result.count)) {
        result.status = Tcps_Bad;
    } else {
        result.status = Tcps_Good;
    }

    return result;
}

unsigned int ocall_GetTickCount(void)
{
    return GetTickCount();
}

uint64_t ocall_time64(void)
{
    uint64_t t;
    _time64((__time64_t*)&t);
    return t;
}

GetTm_Result ocall_localtime64(uint64_t timer)
{
    GetTm_Result result;
    result.err = _localtime64_s((struct tm*)&result.tm, (const __time64_t*)&timer);
    return result;
}

GetTm_Result ocall_gmtime64(uint64_t timer)
{
    GetTm_Result result;
    result.err = _gmtime64_s((struct tm*)&result.tm, (const __time64_t*)&timer);
    return result;
}

/* Process/thread-related APIs */

Tcps_StatusCode ocall_exit(int result)
{
    _exit(result);
    return Tcps_Good;
}

/* We currently use a global mutex.  In the future, this should
 * be changed to a per-TA mutex.
 */
int g_GlobalMutexInitialized = 0;
CRITICAL_SECTION g_GlobalMutex;

oe_result_t oe_acquire_enclave_mutex(_In_ oe_enclave_t* enclave)
{
    oe_result_t result = OE_OK;

    TCPS_UNUSED(enclave);

    if (!g_GlobalMutexInitialized) {
        InitializeCriticalSection(&g_GlobalMutex);
        g_GlobalMutexInitialized++;
    }
    //printf("+ecall: %x\n", GetCurrentThreadId());
    
    for(;;) {
        if (TryEnterCriticalSection(&g_GlobalMutex)) {
            /* Mutex acquired successfully */
            break;
        }

        /* Check if another thread requested this thread to terminate. */
        if (Tcps_P_Thread_WasTerminationRequested()) {
            Tcps_Trace(
                Tcps_TraceLevelWarning,
                "%s: abandoning!\n", 
                __FUNCTION__);
            result = OE_ENCLAVE_ABORTING;
            break;
        }

        Sleep(100);
    }

    return result;
}

void oe_release_enclave_mutex(_In_ oe_enclave_t* enclave)
{
    TCPS_UNUSED(enclave);
    LeaveCriticalSection(&g_GlobalMutex);
    //printf("-ecall: %x\n", GetCurrentThreadId());
}
