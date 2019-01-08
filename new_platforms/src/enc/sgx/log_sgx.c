/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <sgx_trts.h>
#include <sgx_thread.h>
#include <sgx_tae_service.h>
#include <string.h>
#include <unistd.h>
#include <openenclave/enclave.h>
#include <openenclave/bits/stdio.h>
#include <cbor.h>
#include "cborhelper.h"
#include "oeinternal_t.h"
#include "enclavelibc.h"
#include "ICertUtil.h"
#include "tcps.h"

#include "log_sgx.h"
#include "log_ocall_file.h"

#ifdef TCPS_SERVICES_SDK
#include "TcpsLogEthereum.h"
#endif
#define TRANSACTION_HASH_NAME "\"result\":\""
#define TRANSACTION_HASH_LENGTH (32*2 + 2 + 1)

typedef struct _TCPS_LOG_SGX_SERVICES_DATA {
    TCPS_LOG_ID EventId;
    const char* LogIdentityLabel; // TCPS_IDENTITY_LOG
} TCPS_LOG_SGX_SERVICES_DATA;

typedef struct _TCPS_LOG_SGX_OBJECT {
    void* LogHandle;
    
    sgx_thread_mutex_t LockMutex;
    TCPS_TA_ID_INFO *IdentityData;
    TCPS_LOG_SGX_CONFIGURATION LogConfiguration;
} TCPS_LOG_SGX_OBJECT;

static __time64_t g_ProvisionedTime = 0;

extern TRANSPORT_CALLBACKS g_TransportClientCallbacks;

oe_result_t
TcpsLogFileWriteEntrySgx(
    void* Handle,
    const uint8_t* const Buffer,
    const size_t BufferSize,
    const TCPS_IDENTITY_LOG LogIdentityLabel
)
{
    if (Handle == NULL ||
        Buffer == NULL ||
        LogIdentityLabel == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    TCPS_LOG_SGX_OBJECT* context = (TCPS_LOG_SGX_OBJECT*)Handle;
    TCPS_LOG_OCALL_OBJECT ocallContext;
    ocallContext.LogPathPrefix = context->LogConfiguration.LogPathPrefix;

    return TcpsLogFileWriteEntryOcall(
        &ocallContext,
        Buffer,
        BufferSize,
        LogIdentityLabel);
}

oe_result_t
TcpsLogNetworkWriteEntrySgx(
    void* Handle,
    const uint8_t* const Buffer,
    const size_t BufferSize,
    const TCPS_IDENTITY_LOG Identity
)
{
    OE_UNUSED(Identity);

    oe_result_t status = OE_OK;

    if (Buffer == NULL ||
        Handle == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    TCPS_LOG_SGX_OBJECT* logObject = (TCPS_LOG_SGX_OBJECT*)Handle;

    if (logObject->LogConfiguration.RemoteType != TCPS_LOG_SGX_REMOTE_TYPE_LOGAGGREGATOR)
    {
        return OE_FAILURE;
    }

    TCPS_TLS_HANDLE tls = NULL;
    
    uint8_t* laResponseBuffer;
    uint32_t laResponseBufferSize;

    laResponseBuffer = NULL;

    TCPS_CONNECTION_CTX connection;
    memset(&connection, 0, sizeof(connection));
    connection.TptCB = g_TransportClientCallbacks;

    status = TcpsTlsConnectClient(
        logObject->IdentityData,
        &connection, 
        (const uint8_t*)logObject->LogConfiguration.RemoteData.LA.LaTrustedCa, 
        strlen(logObject->LogConfiguration.RemoteData.LA.LaTrustedCa), 
        logObject->LogConfiguration.RemoteIpAddress, 
        logObject->LogConfiguration.RemotePort, 
        0, 
        &tls);
    if (status != OE_OK)
    {
        goto Exit;
    }

    status = TcpsTlsWrite(
        tls,
        Buffer,
        BufferSize,
        0);

    if (status != OE_OK)
    {
        goto Exit;
    }

    status = TcpsTlsRead(
        tls,
        &laResponseBuffer,
        &laResponseBufferSize,
        0 /* TODO: support timeouts */);

    if (status != OE_OK)
    {
        goto Exit;
    }

    if (laResponseBufferSize != sizeof(status))
    {
        status = OE_FAILURE;
        goto Exit;
    }

    status = *(oe_result_t*)laResponseBuffer;

Exit:
    if (tls != NULL)
    {
        TcpsTlsCloseHandle(tls);
    }

    if (laResponseBuffer != NULL)
    {
        oe_free(laResponseBuffer);
    }

    return status;
}

oe_result_t
TcpsLogFileReadSgx(
    void* Handle,
    uint8_t** const Buffer,
    size_t* const BufferSize,
    const TCPS_LOG_FILE_TYPE FileType,
    const TCPS_IDENTITY_LOG LogIdentityLabel
)
{
    if (Buffer == NULL ||
        BufferSize == NULL ||
        Handle == NULL ||
        LogIdentityLabel == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    TCPS_LOG_SGX_OBJECT* context = (TCPS_LOG_SGX_OBJECT*)Handle;
    TCPS_LOG_OCALL_OBJECT ocallContext;
    ocallContext.LogPathPrefix = context->LogConfiguration.LogPathPrefix;

    return TcpsLogFileReadOcall(
        &ocallContext,
        Buffer,
        BufferSize,
        FileType,
        LogIdentityLabel);
}

oe_result_t
TcpsLogFilePullSgx(
    void* Handle,
    uint8_t** const Buffer,
    size_t* const BufferSize,
    const TCPS_IDENTITY_LOG LogIdentityLabel
)
{
    if (Buffer == NULL ||
        BufferSize == NULL ||
        Handle == NULL ||
        LogIdentityLabel == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    *Buffer = NULL;

    oe_result_t status = TcpsLogFileReadSgx(
        Handle, 
        Buffer, 
        BufferSize, 
        TCPS_LOG_FILE_TYPE_LOG, 
        LogIdentityLabel);
    if (status != OE_OK)
    {
        goto Exit;
    }

Exit:
    if (status != OE_OK)
    {
        if (*Buffer != NULL)
        {
            oe_free(*Buffer);
        }
    }

    return status;
}

oe_result_t
TcpsLogFileClearSgx(
    void* Handle,
    const TCPS_IDENTITY_LOG LogIdentityLabel
)
{
    if (Handle == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    TCPS_LOG_SGX_OBJECT* context = (TCPS_LOG_SGX_OBJECT*)Handle;
    TCPS_LOG_OCALL_OBJECT ocallContext;
    ocallContext.LogPathPrefix = context->LogConfiguration.LogPathPrefix;

    return TcpsLogFileClearOcall(
        &ocallContext,
        LogIdentityLabel);
}

oe_result_t
TcpsLogNetworkFlushSgx(
    void* Handle,
    const TCPS_IDENTITY_LOG LogIdentityLabel
)
{
    uint8_t* buffer = NULL;
    size_t bufferSize;
    oe_result_t status = OE_OK;

    status = TcpsLogRemoteFlushCreate(LogIdentityLabel, &buffer, &bufferSize);
    if (status != OE_OK)
    {
        goto Exit;
    }

    status = TcpsLogNetworkWriteEntrySgx(Handle, buffer, bufferSize, NULL);
    if (status != OE_OK)
    {
        goto Exit;
    }

Exit:
    if (buffer != NULL)
    {
        oe_free(buffer);
    }

    return status;
}

oe_result_t
TcpsLogCounterRecoverSgx(
    void* Handle,
    uint8_t** const CounterBuffer,
    size_t* const CounterBufferSize,
    const TCPS_IDENTITY_LOG LogIdentityLabel
)
{
    if (CounterBuffer == NULL ||
        CounterBufferSize == NULL ||
        Handle == NULL ||
        LogIdentityLabel == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    *CounterBuffer = NULL;

    oe_result_t status = TcpsLogFileReadSgx(
        Handle, 
        CounterBuffer, 
        CounterBufferSize, 
        TCPS_LOG_FILE_TYPE_SIG, 
        LogIdentityLabel);
    if (status != OE_OK)
    {
        goto Exit;
    }

Exit:
    if (status != OE_OK)
    {
        if (*CounterBuffer != NULL)
        {
            oe_free(*CounterBuffer);
        }
    }

    return status;
}

oe_result_t
TcpsLogCounterWriteSgx(
    void* Handle,
    const uint8_t* const CounterBuffer,
    const size_t CounterBufferSize,
    const TCPS_IDENTITY_LOG LogIdentityLabel
)
{
    if (Handle == NULL ||
        LogIdentityLabel == NULL ||
        CounterBuffer == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    TCPS_LOG_SGX_OBJECT* context = (TCPS_LOG_SGX_OBJECT*)Handle;
    TCPS_LOG_OCALL_OBJECT ocallContext;
    ocallContext.LogPathPrefix = context->LogConfiguration.LogPathPrefix;

    return TcpsLogFileWriteOcall(
        &ocallContext,
        CounterBuffer,
        CounterBufferSize,
        TCPS_LOG_FILE_TYPE_SIG,
        false,
        LogIdentityLabel);
}

// Define sleep to be a no-op for now.
// TODO: rewrite TcpsLogSgxEstablishPSESession to not block a thread.
#define ocallTcpsSleep(x)

oe_result_t
TcpsLogSgxEstablishPSESession()
{
    // Connect to platform service enclave
    sgx_status_t ret = 0;
    int busy_retry_times = 2;
    do
    {
        if (busy_retry_times != 2)
        {
            ocallTcpsSleep(1000);
        }
        ret = sgx_create_pse_session();
    } while (ret == SGX_ERROR_BUSY && busy_retry_times--);

    return ret == SGX_SUCCESS ? OE_OK : OE_FAILURE;
}

void
TcpsLogTimeProvisionSgx(
    __time64_t UntrustedTime
)
{
    g_ProvisionedTime = UntrustedTime;
    TcpsLogSgxEstablishPSESession();
}

__time64_t
TcpsLogUntrustedTimeSgx(__time64_t* Timer)
{
    __time64_t result;
    sgx_status_t status = ocall_time64(&result);

    if (status != SGX_SUCCESS)
    {
        result = -1;
    }
    if (Timer != Tcps_Null)
    {
        *Timer = result;
    }

    return result;
}

__time64_t
TcpsLogTrustedTimeSgx(
    __time64_t* seconds
)
{
    static int init = 0;
    static sgx_time_source_nonce_t ref_nonce = { 0 };
    static __time64_t time_offset;
    __time64_t result = -1;
    sgx_status_t ret;

    if (TcpsLogSgxEstablishPSESession() == OE_FAILURE)
    {
        return TcpsLogUntrustedTimeSgx(NULL);
        //return g_ProvisionedTime;
    }

    // Initialize reference time source (nonce)
    if (!init)
    {
        sgx_time_t ref_timestamp;
        ret = sgx_get_trusted_time(&ref_timestamp, &ref_nonce);
        if (ret != SGX_SUCCESS)
        {
            goto Exit;
        }

        time_offset = (__time64_t)(g_ProvisionedTime - ref_timestamp);

        init = 1;
    }

    sgx_time_source_nonce_t current_nonce;
    sgx_time_t current_timestamp;
    ret = sgx_get_trusted_time(&current_timestamp, &current_nonce);
    if (ret != SGX_SUCCESS)
    {
        goto Exit;
    }

    // The Intel developer SDK suggests that the caller should compare time_source_nonce 
    // against the value returned from the previous call of sgx_get_trusted_time if it 
    // needs to calculate the time passed between two readings of the Trusted Timer. 
    // If the time_source_nonce of the two readings do not match, the difference between 
    // the two readings does not necessarily reflect time passed.
    if (memcmp(&ref_nonce, &current_nonce, sizeof(sgx_time_source_nonce_t)))
    {
        init = 0;
        goto Exit;
    }

    result = (__time64_t)current_timestamp + time_offset;

    if (seconds)
    {
        *seconds = result;
    }

Exit:
    return result;
}

oe_result_t
TcpsLogCounterValidateSgx(
    void* Handle,
    const uint8_t* const CounterIdBuffer,
    const size_t CounterIdBufferSize,
    const uint8_t* const CounterValueBuffer,
    const size_t CounterValueBufferSize
)
{
    oe_result_t status = OE_OK;

    if (Handle == NULL ||
        CounterIdBuffer == NULL ||
        CounterValueBuffer == NULL ||
        sizeof(sgx_mc_uuid_t) != CounterIdBufferSize ||
        sizeof(uint32_t) != CounterValueBufferSize)
    {
        return OE_INVALID_PARAMETER;
    }

    sgx_mc_uuid_t* uuid = (sgx_mc_uuid_t*)CounterIdBuffer;
    uint32_t* counterValue = (uint32_t*)CounterValueBuffer;

    uint32_t actualCounterValue;
    sgx_status_t ret = sgx_read_monotonic_counter(uuid, &actualCounterValue);
    if (ret != SGX_SUCCESS)
    {
        status = OE_FAILURE; // TODO this can fail on replay
        goto Exit;
    }

    if (actualCounterValue != *counterValue)
    {
        status = OE_FAILURE; // TODO this can fail on replay or suffix delete
        goto Exit;
    }

Exit:
    return status;
}

oe_result_t
TcpsLogCounterCreateSgx(
    void* Handle,
    uint8_t** const CounterIdBuffer,
    size_t* const CounterIdBufferSize,
    uint8_t** const CounterValueBuffer,
    size_t* const CounterValueBufferSize
)
{
    oe_result_t status = OE_OK;

    if (Handle == NULL ||
        CounterIdBuffer == NULL ||
        CounterIdBufferSize == NULL ||
        CounterValueBuffer == NULL ||
        CounterValueBufferSize == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    uint8_t* localCounterIdBuffer = NULL;
    uint8_t* localCounterValueBuffer = NULL;

    *CounterIdBufferSize = sizeof(sgx_mc_uuid_t);
    localCounterIdBuffer = oe_malloc(*CounterIdBufferSize);
    if (localCounterIdBuffer == NULL)
    {
        status = OE_OUT_OF_MEMORY;
        goto Exit;
    }

    *CounterValueBufferSize = sizeof(uint32_t);
    localCounterValueBuffer = oe_malloc(*CounterValueBufferSize);
    if (localCounterValueBuffer == NULL)
    {
        status = OE_OUT_OF_MEMORY;
        goto Exit;
    }

    sgx_status_t ret = sgx_create_monotonic_counter(
        (sgx_mc_uuid_t*)localCounterIdBuffer, 
        (uint32_t*)localCounterValueBuffer); // TODO consider more strict policy
    if (ret != SGX_SUCCESS)
    {
        status = OE_FAILURE; // TODO this might fail if the number of counters have been exhausted
        goto Exit;
    }

    *CounterIdBuffer = localCounterIdBuffer;
    localCounterIdBuffer = NULL;
    *CounterValueBuffer = localCounterValueBuffer;
    localCounterValueBuffer = NULL;

Exit:
    if (localCounterIdBuffer != NULL)
    {
        oe_free(localCounterIdBuffer);
    }

    if (localCounterValueBuffer != NULL)
    {
        oe_free(localCounterValueBuffer);
    }

    return status;
}

oe_result_t
TcpsLogCounterIncrementGetSgx(
    void* Handle,
    const uint8_t* const CounterIdBuffer,
    const size_t CounterIdBufferSize,
    uint8_t** const CounterValueBuffer,
    size_t* CounterValueBufferSize
)
{
    oe_result_t status = OE_OK;

    if (Handle == NULL ||
        CounterIdBuffer == NULL ||
        CounterIdBufferSize != sizeof(sgx_mc_uuid_t) ||
        CounterValueBuffer == NULL ||
        CounterValueBufferSize == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    sgx_status_t ret = 0;
    uint8_t* localCounterValueBuffer = NULL;

    localCounterValueBuffer = oe_malloc(sizeof(uint32_t));
    if (localCounterValueBuffer == NULL)
    {
        status = OE_OUT_OF_MEMORY;
        goto Exit;
    }

    sgx_mc_uuid_t* counterId = (sgx_mc_uuid_t*)CounterIdBuffer;
    uint32_t* localCounterValue = (uint32_t*)localCounterValueBuffer;

    ret = sgx_increment_monotonic_counter(counterId, localCounterValue);
    if (ret != SGX_SUCCESS)
    {
        status = OE_FAILURE; // TODO this can fail on replay
        goto Exit;
    }

    *CounterValueBuffer = localCounterValueBuffer;
    localCounterValueBuffer = NULL;
    *CounterValueBufferSize = sizeof(uint32_t);

Exit:
    if (localCounterValueBuffer != NULL)
    {
        oe_free(localCounterValueBuffer);
    }

    return status;
}

oe_result_t
TcpsLogInitSgx(
    const TCPS_SHA256_DIGEST Seed,
    TCPS_TA_ID_INFO* const IDData,
    const TCPS_LOG_SGX_CONFIGURATION* const Configuration,
    const bool EnableRollbackProtection,
    void** Handle
)
{
    oe_result_t status = OE_OK;
    bool mutexInitialized = false;
    bool pseWorks = false;

    if (IDData == NULL ||
        Configuration == NULL ||
        Seed == NULL ||
        Handle == NULL)
    {
        return OE_FAILURE;
    }

    TCPS_LOG_SGX_OBJECT* logObject = oe_malloc(sizeof(TCPS_LOG_SGX_OBJECT));
    if (logObject == NULL)
    {
        status = OE_OUT_OF_MEMORY;
        goto Exit;
    }
    memset(logObject, 0, sizeof(TCPS_LOG_SGX_OBJECT));

    memcpy(&logObject->LogConfiguration, Configuration, sizeof(logObject->LogConfiguration));
    logObject->IdentityData = IDData;

    PTCPS_LOG_WRITE remoteLog = NULL;
    PTCPS_LOG_IDENTITY remoteLogFlush = NULL;
    bool enableRemote = logObject->LogConfiguration.RemoteType != TCPS_LOG_SGX_REMOTE_TYPE_NONE;

    switch (Configuration->RemoteType)
    {
    case TCPS_LOG_SGX_REMOTE_TYPE_LOGAGGREGATOR:
        remoteLog = TcpsLogNetworkWriteEntrySgx;
        remoteLogFlush = TcpsLogNetworkFlushSgx;
        break;

#ifdef TCPS_SERVICES_SDK
    case TCPS_LOG_SGX_REMOTE_TYPE_BLOCKCHAIN:
        remoteLog = TcpsLogEthereumWriteEntrySgx;
        break;
#endif

    case TCPS_LOG_SGX_REMOTE_TYPE_NONE:
    default:
        enableRemote = false;
        break;
    }

    // TODO this can secretly fallback, needed for ACC, since it is not 
    // implementing PSE for the time being, fix before shipping
    if (!enableRemote && EnableRollbackProtection)
    {
        // Connect to platform service enclave
        pseWorks = TcpsLogSgxEstablishPSESession() == OE_OK;
    }

    status = TcpsLogInit(
        &IDData->CompoundPrivKey,
        &IDData->CompoundPubKey,
        TcpsLogFileWriteEntrySgx,
        true,
        enableRemote ? TcpsLogFilePullSgx : NULL,
        enableRemote ? TcpsLogFileClearSgx : NULL,
        remoteLog,
        remoteLogFlush, // TODO this might be NULL despite remote callback !null
        pseWorks ? TcpsLogCounterRecoverSgx : NULL,
        pseWorks ? TcpsLogCounterWriteSgx : NULL,
        pseWorks ? TcpsLogCounterValidateSgx : NULL,
        pseWorks ? TcpsLogCounterCreateSgx : NULL,
        pseWorks ? TcpsLogCounterIncrementGetSgx : NULL,
        logObject->LogConfiguration.TimeFunc,
        Seed,
        logObject,
        &logObject->LogHandle);
    if (status != OE_OK)
    {
        goto Exit;
    }

    sgx_thread_mutexattr_t dummy;
    int result = sgx_thread_mutex_init(&logObject->LockMutex, &dummy);
    if (result != 0)
    {
        status = OE_FAILURE;
        goto Exit;
    }
    mutexInitialized = true;

    *Handle = logObject;
    logObject = NULL;

Exit:
    if (logObject != NULL)
    {
        TcpsLogClose(logObject->LogHandle);
        if (mutexInitialized)
        {
            sgx_thread_mutex_destroy(&logObject->LockMutex);
        }
        oe_free(logObject);
        if (pseWorks)
        {
            sgx_close_pse_session();
        }
    }

    return status;
}

void
TcpsLogCloseSgx(
    void* Handle
)
{
    if (Handle != NULL)
    {
        TCPS_LOG_SGX_OBJECT* logObject = (TCPS_LOG_SGX_OBJECT*)Handle;

        sgx_thread_mutex_destroy(&logObject->LockMutex);
        TcpsLogClose(logObject->LogHandle);
        oe_free(logObject);
        sgx_close_pse_session();
    }
}

oe_result_t
TcpsLogEventSgx(
    void* Handle,
    const uint8_t* const Buffer,
    const size_t BufferSize,
    const bool Flush
)
{
    oe_result_t status = OE_OK;

    if (Handle == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    TCPS_LOG_SGX_OBJECT* logObject = (TCPS_LOG_SGX_OBJECT*)Handle;

    int result = sgx_thread_mutex_lock(&logObject->LockMutex);
    if (result != 0)
    {
        status = OE_FAILURE;
        goto Exit;
    }

    status = TcpsLogEvent(logObject->LogHandle, Buffer, BufferSize, Flush);

    result = sgx_thread_mutex_unlock(&logObject->LockMutex);
    if (result != 0)
    {
        status = OE_FAILURE;
        goto Exit;
    }

Exit:
    return status;
}

oe_result_t
TcpsLogEventExistingSgx(
    void* Handle,
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_VALIDATION_STATE* const ValidationState
)
{
    oe_result_t status = OE_OK;

    if (Handle == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    TCPS_LOG_SGX_OBJECT* logObject = (TCPS_LOG_SGX_OBJECT*)Handle;

    int result = sgx_thread_mutex_lock(&logObject->LockMutex);
    if (result != 0)
    {
        status = OE_FAILURE;
        goto Exit;
    }

    status = TcpsLogEventExisting(logObject->LogHandle, Buffer, BufferSize, ValidationState);

    result = sgx_thread_mutex_unlock(&logObject->LockMutex);
    if (result != 0)
    {
        status = OE_FAILURE;
        goto Exit;
    }

Exit:
    return status;
}

oe_result_t
TcpsLogEventSgxId(
    void* Handle,
    const TCPS_LOG_ID EventId,
    const bool Flush
)
{
    oe_result_t status = OE_OK;
    TCPS_IDENTITY_LOG dummy = { 0 };

    status = TcpsLogEventSgxPeerId(Handle, EventId, dummy, Flush);

    return status;
}

CborError
TcpsCborEncodeSgxServicesEvent(
    const TCPS_LOG_SGX_SERVICES_DATA* const Payload,
    size_t* const BufferSize,
    uint8_t* const Buffer
)
/*++

Routine Description:

Parameters:

--*/
{
    CborError err = CborNoError;

    if (BufferSize == NULL ||
        (*BufferSize > 0 && Buffer == NULL) ||
        Payload == NULL ||
        Payload->LogIdentityLabel == NULL)
    {
        return CborErrorInternalError;
    }

    CborEncoder encoder, arrayEncoder;
    cbor_encoder_init(&encoder, Buffer, *BufferSize, 0);
    CLEANUP_ENCODER_ERR(cbor_encoder_create_array(&encoder, &arrayEncoder, 2));
    CLEANUP_ENCODER_ERR(cbor_encode_uint(&arrayEncoder, Payload->EventId));
    CLEANUP_ENCODER_ERR(cbor_encode_byte_string(
        &arrayEncoder, 
        (const uint8_t*) Payload->LogIdentityLabel, 
        sizeof(TCPS_IDENTITY_LOG)));
    err = cbor_encoder_close_container_checked(&encoder, &arrayEncoder);
    if (err != CborNoError && err != CborErrorOutOfMemory)
    {
        goto Cleanup;
    }

    *BufferSize = cbor_encoder_get_extra_bytes_needed(&encoder);
    if (*BufferSize)
    {
        err = CborErrorOutOfMemory;
        goto Cleanup;
    }

    *BufferSize = cbor_encoder_get_buffer_size(&encoder, Buffer);

Cleanup:
    return err;
}

CborError
TcpsCborDecodeSgxServicesEvent(
    CborValue* const Value,
    TCPS_LOG_SGX_SERVICES_DATA* const Payload
)
/*++

Routine Description:

Parameters:

--*/
{
    size_t logIdentityLabelSize = sizeof(TCPS_IDENTITY_LOG);
    uint64_t eventId64;
    CborError err = CborNoError;

    if (Value == NULL ||
        Payload == NULL)
    {
        return CborErrorInternalError;
    }

    // EventId

    if (!cbor_value_is_unsigned_integer(Value))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_get_uint64(Value, &eventId64));
    if (eventId64 > UINT32_MAX)
    {
        err = CborErrorUnknownType;
        goto Cleanup;
    }
    Payload->EventId = (TCPS_LOG_ID)eventId64;
    CLEANUP_DECODER_ERR(cbor_value_advance_fixed(Value));

    // Log identity label

    if (!cbor_value_is_byte_string(Value))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_ref_byte_string(
        Value, 
        (const uint8_t**) &Payload->LogIdentityLabel, 
        &logIdentityLabelSize, 
        Value));
    if (logIdentityLabelSize != sizeof(TCPS_IDENTITY_LOG))
    {
        err = CborErrorUnknownType;
        goto Cleanup;
    }

Cleanup:
    return err;
}

oe_result_t
TcpsLogEventSgxPeerId(
    void* Handle,
    const TCPS_LOG_ID EventId,
    const TCPS_IDENTITY_LOG IdentityLabel,
    const bool Flush
)
{
    oe_result_t status = OE_OK;
    TCPS_LOG_SGX_SERVICES_DATA eventData;
    uint8_t* payloadBuffer = NULL;
    size_t payloadBufferSize = 0;

    eventData.EventId = EventId;
    eventData.LogIdentityLabel = IdentityLabel;

    CborError err = TcpsCborEncodeSgxServicesEvent(
        &eventData,
        &payloadBufferSize,
        payloadBuffer);
    if (err == CborErrorOutOfMemory)
    {
        payloadBuffer = (uint8_t*)oe_malloc(payloadBufferSize);
        if (payloadBuffer == NULL)
        {
            status = OE_OUT_OF_MEMORY;
            goto Exit;
        }

        err = TcpsCborEncodeSgxServicesEvent(
            &eventData,
            &payloadBufferSize,
            payloadBuffer);
    }

    if (err != CborNoError)
    {
        status = OE_FAILURE;
        goto Exit;
    }

    status = TcpsLogEventSgx(Handle, payloadBuffer, payloadBufferSize, Flush);

Exit:
    if (payloadBuffer != NULL)
    {
        oe_free(payloadBuffer);
    }

    return status;
}

oe_result_t
TcpsGetPeerIdentityLabel(
    TCPS_TLS_HANDLE TlsHandle,
    TCPS_IDENTITY_LOG IdentityLabel
)
{
    oe_result_t status;
    RIOT_ECC_PUBLIC peerPublicKey;

    status = TcpsTlsGetPublicKeyFromPeer(TlsHandle, &peerPublicKey);
    if (status != OE_OK)
    {
        goto Exit;
    }

    status = TcpsGetDeviceIdStrFromPublic(
        &peerPublicKey,
        IdentityLabel,
        sizeof(TCPS_IDENTITY_LOG));

    if (status != OE_OK)
    {
        goto Exit;
    }

Exit:
    return status;
};

