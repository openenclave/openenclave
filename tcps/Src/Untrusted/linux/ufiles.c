/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stddef.h>

#include "sal_unsup.h"

#include <tcps.h>
#include <openenclave/bits/result.h>

#include "TcpsCalls_u.h"

Tcps_StatusCode 
ocall_ExportPublicCertificate(
    buffer256 certificateFileNameExported, 
    buffer4096 ptr, 
    size_t len)
{
    Tcps_Trace(Tcps_TraceLevelDebug, "ocall_ExportPublicCertificate: export to (%s)\n", certificateFileNameExported);

    return ocall_ExportFile(certificateFileNameExported, Tcps_False, ptr, len);
}

FindFirstUntrustedFile_Result
ocall_FindFirstUntrustedFile(
    buffer256 filePathWithWildcards,
    uint32_t matchingFileNameSize)
{
    FindFirstUntrustedFile_Result result = { 0 };
    result.status = OE_UNSUPPORTED;

    return result;
}

FindNextUntrustedFile_Result
ocall_FindNextUntrustedFile(
    uint32_t findNextHandle,
    uint32_t matchingFileNameSize)
{
    FindNextUntrustedFile_Result result = { 0 };
    result.result = OE_UNSUPPORTED;
    
    return result;
}

Tcps_StatusCode 
ocall_FindNextUntrustedFileClose(
    uint32_t findNextHandle)
{
    return Tcps_BadNotImplemented;
}
