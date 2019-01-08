/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stddef.h>

#include "sal_unsup.h"

#include <tcps.h>
#include <openenclave/bits/result.h>

#include "stdio_u.h"

oe_result_t
ocall_ExportPublicCertificate(
    const char* certificateFileNameExported,
    const void* ptr,
    size_t len)
{
    Tcps_Trace(Tcps_TraceLevelDebug, "ocall_ExportPublicCertificate: export to (%s)\n", certificateFileNameExported);

    return ocall_ExportFile(certificateFileNameExported, Tcps_False, ptr, len);
}

FindFirstUntrustedFile_Result
ocall_opendir(
    const char* filePathWithWildcards,
    uint32_t matchingFileNameSize)
{
    FindFirstUntrustedFile_Result result = { 0 };
    result.status = OE_UNSUPPORTED;

    return result;
}

ocall_struct_dirent
ocall_readdir(
    uintptr_t findNextHandle,
    uint32_t matchingFileNameSize)
{
    ocall_struct_dirent result = { 0 };
    result.status = OE_UNSUPPORTED;
   
    return result;
}

oe_result_t
ocall_closedir(
    uintptr_t findNextHandle)
{
    return OE_UNSUPPORTED;
}
