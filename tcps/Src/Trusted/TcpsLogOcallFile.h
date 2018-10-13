/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

typedef enum 
{
    // denotes the actual log file
    TCPS_LOG_FILE_TYPE_LOG,

    // denotes the signature cookie file with the monotonic counter and chain hash
    TCPS_LOG_FILE_TYPE_SIG,

} TCPS_LOG_FILE_TYPE;

typedef struct _TCPS_LOG_OCALL_OBJECT {
    char* LogPathPrefix;
} TCPS_LOG_OCALL_OBJECT;

Tcps_StatusCode
TcpsLogFileWriteOcall(
    TCPS_LOG_OCALL_OBJECT* Context,
    const uint8_t* const Buffer,
    const size_t BufferSize,
    const TCPS_LOG_FILE_TYPE FileType,
    bool Append,
    const TCPS_IDENTITY_LOG LogIdentityLabel
);

Tcps_StatusCode
TcpsLogFileReadOcall(
    TCPS_LOG_OCALL_OBJECT* Context,
    uint8_t** const Buffer,
    size_t* const BufferSize,
    const TCPS_LOG_FILE_TYPE FileType,
    const TCPS_IDENTITY_LOG LogIdentityLabel
);

Tcps_StatusCode
TcpsLogFileClearOcall(
    TCPS_LOG_OCALL_OBJECT* Context,
    const TCPS_IDENTITY_LOG LogIdentityLabel
);

Tcps_StatusCode
TcpsLogFileWriteEntryOcall(
    TCPS_LOG_OCALL_OBJECT* Context,
    const uint8_t* const Buffer,
    const size_t BufferSize,
    const TCPS_IDENTITY_LOG LogIdentityLabel
);
