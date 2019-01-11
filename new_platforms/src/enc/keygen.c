/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <stdlib.h>

#include "tcps_string_t.h"
#include "enclavelibc.h"

int ExportPublicCertificate(const char* sourceLocation, const char* destinationPath)
{
    char* ptr;
    size_t len;
    int err;
    oe_result_t uStatus;

    uStatus = GetTrustedFileInBuffer(sourceLocation, &ptr, &len);
    if (uStatus != OE_OK) {
        return uStatus;
    }

    err = TEE_P_ExportPublicCertificate(destinationPath, ptr, len);

    // Free the buffer.
    FreeTrustedFileBuffer(ptr);

    return err;
}

/* Returns 0 on success, non-zero on error */
oe_result_t Provision_Certificate(const char* destinationLocation, const char* sourceLocation)
{
    /* Import the file and add it to the manifest. */
    return TEE_P_ImportFile(destinationLocation, sourceLocation, TRUE);
}

#if 0
oe_result_t
TEE_P_ExportPublicCertificate(
    _In_z_ const char* certificateFileNameExported,
    _Out_writes_(len) char* ptr,
    _In_ size_t len)
{
    sgx_status_t sgxStatus;
    oe_result_t retval;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "TEE_P_ExportPublicCertificate");

    Tcps_Trace(Tcps_TraceLevelDebug, "***************** export to (%s)\n", certificateFileNameExported);

    sgxStatus = ocall_ExportPublicCertificate(
        &retval,
        certificateFileNameExported,
        ptr,
        len);

    uStatus = retval;

    Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, OE_FAILURE);
    Tcps_GotoErrorIfBad(uStatus);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
    Tcps_Trace(Tcps_TraceLevelError, "sgxStatus = %#x\n", sgxStatus);
Tcps_FinishErrorHandling;
}
#endif
