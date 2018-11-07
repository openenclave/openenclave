/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/enclave.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#ifdef USE_OPTEE
#include "tcps_time_t.h"
#include "tcps_string_t.h"
#include "oeoverintelsgx_t.h"
#include <optee/tcps_string_optee_t.h>
#else
#include "oeoverintelsgx_t.h"
#endif

#include "TcpsLog.h"
#include "TcpsLogOcallFile.h"
#include <stdio.h>
#include "enclavelibc.h"

static
char*
TcpsLogFilenameFormatOcall(
    const char* const Prefix,
    const TCPS_LOG_FILE_TYPE Type,
    const TCPS_IDENTITY_LOG IdentityLog)
{
    static char path[255];
    const char* typeLabel;
    int result;

    switch (Type)
    {
    case TCPS_LOG_FILE_TYPE_LOG:
        typeLabel = "log";
        break;

    case TCPS_LOG_FILE_TYPE_SIG:
        typeLabel = "sig";
        break;

    default:
        return NULL;
    }
    result = snprintf(
        path, 
        sizeof(path), 
        "%s_%s_%s.dat", 
        Prefix, 
        typeLabel, 
        IdentityLog);
    if (result < 0 || result >= (int)sizeof(path))
    {
        return NULL;
    }

    return path;
}

Tcps_StatusCode
TcpsLogFileWriteOcall(
    TCPS_LOG_OCALL_OBJECT* Context,
    const uint8_t* const Buffer,
    const size_t BufferSize,
    const TCPS_LOG_FILE_TYPE FileType,
    bool Append,
    const TCPS_IDENTITY_LOG LogIdentityLabel)
{
    oe_buffer256 filenameBuffer;
    oe_buffer4096* content;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "TcpsLogFileWriteOcall");

    Tcps_ReturnErrorIfArgumentNull(Context);
    Tcps_ReturnErrorIfArgumentNull(Buffer);
    Tcps_ReturnErrorIfArgumentNull(LogIdentityLabel);

    unsigned int result = 1;
    const char* filename = TcpsLogFilenameFormatOcall(
        Context->LogPathPrefix, FileType, LogIdentityLabel);
    Tcps_ReturnErrorIfTrue(filename == NULL, Tcps_Bad);

    COPY_BUFFER_FROM_STRING(filenameBuffer, filename);

    content = (oe_buffer4096*)oe_malloc(sizeof(*content));
    Tcps_GotoErrorIfAllocFailed(content);

    COPY_BUFFER(*content, Buffer, BufferSize);

    sgx_status_t sgxResult = ocall_ExportFile(&result, filenameBuffer, Append, *content, BufferSize);

    oe_free(content);

    Tcps_GotoErrorIfTrue(sgxResult != SGX_SUCCESS, Tcps_Bad);
    Tcps_GotoErrorIfTrue(result != 0, Tcps_Bad);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
Tcps_FinishErrorHandling;
}

Tcps_StatusCode
TcpsLogFileWriteEntryOcall(
    TCPS_LOG_OCALL_OBJECT* Context,
    const uint8_t* const Buffer,
    const size_t BufferSize,
    const TCPS_IDENTITY_LOG LogIdentityLabel)
{
    if (Context == NULL ||
        Buffer == NULL ||
        LogIdentityLabel == NULL)
    {
        return Tcps_BadInvalidArgument;
    }

    return TcpsLogFileWriteOcall(
        Context,
        Buffer,
        BufferSize,
        TCPS_LOG_FILE_TYPE_LOG,
        true,
        LogIdentityLabel);
}

Tcps_StatusCode
TcpsLogFileReadOcall(
    TCPS_LOG_OCALL_OBJECT* Context,
    uint8_t** const Buffer,
    size_t* const BufferSize,
    const TCPS_LOG_FILE_TYPE FileType,
    const TCPS_IDENTITY_LOG LogIdentityLabel)
{
    oe_buffer256 filenameBuffer;

    if (Buffer == NULL ||
        BufferSize == NULL ||
        Context == NULL ||
        LogIdentityLabel == NULL)
    {
        return Tcps_BadInvalidArgument;
    }

    *Buffer = NULL;
    *BufferSize = 0;

    Tcps_StatusCode uStatus = Tcps_Good;
    GetUntrustedFileSize_Result sizeResult;
    GetUntrustedFileContent_Result contentResult;

    const char* filename = TcpsLogFilenameFormatOcall(
        Context->LogPathPrefix,
        FileType,
        LogIdentityLabel);
    if (!filename)
    {
        return Tcps_Bad;
    }

    COPY_BUFFER_FROM_STRING(filenameBuffer, filename);

    sgx_status_t sgxstatus = ocall_GetUntrustedFileSize(&sizeResult, filenameBuffer);

    Tcps_GotoErrorIfTrue(sgxstatus != SGX_SUCCESS, Tcps_Bad);

    if (sizeResult.status)
    {
        // file not found
        goto Error;
    }

    if (sizeResult.fileSize != 0)
    {
        Tcps_GotoErrorIfTrue(sizeResult.fileSize > sizeof(contentResult.content), Tcps_BadRequestTooLarge);

        sgxstatus = ocall_GetUntrustedFileContent(
            &contentResult,
            filenameBuffer,
            sizeResult.fileSize);

        Tcps_GotoErrorIfTrue(sgxstatus != SGX_SUCCESS || contentResult.status, Tcps_Bad);

        *Buffer = oe_malloc(sizeof(sizeResult.fileSize));
        Tcps_GotoErrorIfAllocFailed(*Buffer);
        memcpy(*Buffer, contentResult.content, sizeResult.fileSize);
    }
    *BufferSize = sizeResult.fileSize;

Error:
    if (uStatus != Tcps_Good)
    {
        if (*Buffer != NULL)
        {
            oe_free(*Buffer);
        }
    }

    return uStatus;
}

Tcps_StatusCode
TcpsLogFileClearOcall(
    TCPS_LOG_OCALL_OBJECT* Context,
    const TCPS_IDENTITY_LOG LogIdentityLabel)
{
    Tcps_StatusCode status = Tcps_Good;
    int retVal = 1;

    if (Context == NULL)
    {
        return Tcps_BadInvalidArgument;
    }

    const char* filename = TcpsLogFilenameFormatOcall(
        Context->LogPathPrefix,
        TCPS_LOG_FILE_TYPE_LOG,
        LogIdentityLabel);
    if (!filename)
    {
        return Tcps_Bad;
    }
    oe_buffer256 filenameBuffer;
    COPY_BUFFER_FROM_STRING(filenameBuffer, filename);

    sgx_status_t sgxstatus =
#ifdef USE_OPTEE
        SGX_ERROR_UNEXPECTED;
#else
        ocallTcpsFileDelete(&retVal, filenameBuffer);
#endif

    if (sgxstatus != SGX_SUCCESS || retVal)
    {
        status = Tcps_Bad;
        goto Exit;
    }

Exit:
    return status;
}
