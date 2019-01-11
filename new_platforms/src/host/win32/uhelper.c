/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <time.h>
#include <windows.h> // for LARGE_INTEGER
#include <openenclave/host.h>

#define MIN(a,b) (((a) < b) ? (a) : (b))

/* Time-related APIs */

oe_result_t ocall_QueryPerformanceCounter(_Out_ uint64_t* count)
{

    if (!QueryPerformanceCounter((LARGE_INTEGER*)count)) {
        return OE_FAILURE;
    } else {
        return OE_OK;
    }
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

int ocall_localtime64(uint64_t timer, _Out_ struct ocall_tm* tm)
{
    return _localtime64_s((struct tm*)tm, (const __time64_t*)&timer);
}

int ocall_gmtime64(uint64_t timer, _Out_ struct ocall_tm* tm)
{
    return _gmtime64_s((struct tm*)tm, (const __time64_t*)&timer);
}

/* Process/thread-related APIs */

oe_result_t ocall_exit(int result)
{
    _exit(result);
    return OE_OK;
}

/* We currently use a global mutex.  In the future, this should
 * be changed to a per-TA mutex.
 */
int g_GlobalMutexInitialized = 0;
CRITICAL_SECTION g_GlobalMutex;

oe_result_t oe_acquire_enclave_mutex(_In_ oe_enclave_t* enclave)
{
    oe_result_t result = OE_OK;

    OE_UNUSED(enclave);

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
    OE_UNUSED(enclave);
    LeaveCriticalSection(&g_GlobalMutex);
    //printf("-ecall: %x\n", GetCurrentThreadId());
}
