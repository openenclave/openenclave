/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <windows.h>
#include <tee_api.h>

void TEE_GetREETime(_Out_ TEE_Time* time)
{
    // Get untrusted absolute time from the REE.
    FILETIME fileTime;
    GetSystemTimeAsFileTime(&fileTime);

    ULARGE_INTEGER ulInt;
    ulInt.HighPart = fileTime.dwHighDateTime;
    ulInt.LowPart = fileTime.dwLowDateTime;

    // Convert 100ns intervals to milliseconds.
    time->seconds = (uint32_t)((ulInt.QuadPart / 10000) / 1000);
    time->millis = (uint32_t)((ulInt.QuadPart / 10000) % 1000);
}

void TEE_GetSystemTime(_Out_ TEE_Time* time)
{
    // Get monotonic time elapsed.
    DWORD ticks = GetTickCount();
    time->seconds = ticks / 1000;
    time->millis = ticks % 1000;
}
