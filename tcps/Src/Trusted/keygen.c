/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <stdlib.h>

#include "tcps_string_t.h"
#include "TcpsCalls_t.h"

int ExportPublicCertificate(const char* sourceLocation, const char* destinationPath)
{
    char* ptr;
    size_t len;
    int err;
    Tcps_StatusCode uStatus;

    uStatus = GetTrustedFileInBuffer(sourceLocation, &ptr, &len);
    if (Tcps_IsBad(uStatus)) {
        return uStatus;
    }

    err = TEE_P_ExportPublicCertificate(destinationPath, ptr, len);

    // Free the buffer.
    FreeTrustedFileBuffer(ptr);

    return err;
}

/* Returns 0 on success, non-zero on error */
Tcps_StatusCode Provision_Certificate(const char* destinationLocation, const char* sourceLocation)
{
    /* Import the file and add it to the manifest. */
    return TEE_P_ImportFile(destinationLocation, sourceLocation, TRUE);
}

Tcps_StatusCode
TEE_P_ExportPublicCertificate(
    _In_z_ const char* certificateFileNameExported,
    _Out_writes_(len) char* ptr,
    _In_ size_t len)
{
    sgx_status_t sgxStatus;
    Tcps_StatusCode retval;
    oe_buffer256 certificateFileNameExportedBuffer;
    oe_buffer4096* contents = NULL;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "TEE_P_ExportPublicCertificate");

    Tcps_Trace(Tcps_TraceLevelDebug, "***************** export to (%s)\n", certificateFileNameExported);

    COPY_BUFFER_FROM_STRING(certificateFileNameExportedBuffer, certificateFileNameExported);

    Tcps_GotoErrorIfTrue(len > sizeof(*contents), Tcps_BadRequestTooLarge);

    contents = (oe_buffer4096*)malloc(sizeof(*contents));
    Tcps_GotoErrorIfAllocFailed(contents);

    COPY_BUFFER(*contents, ptr, len);

    sgxStatus = ocall_ExportPublicCertificate(
        &retval,
        certificateFileNameExportedBuffer,
        *contents,
        len);

    free(contents);

    uStatus = retval;

    Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, Tcps_Bad);
    Tcps_GotoErrorIfBad(uStatus);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
    Tcps_Trace(Tcps_TraceLevelError, "sgxStatus = %#x\n", sgxStatus);
Tcps_FinishErrorHandling;
}
