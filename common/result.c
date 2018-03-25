// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/result.h>

// OE abort status depends on the order of these enums to transfer status
// correctly.
OE_STATIC_ASSERT(OE_ENCLAVE_ABORTING > OE_OK);
OE_STATIC_ASSERT(OE_ENCLAVE_ABORTED > OE_ENCLAVE_ABORTING);

const char* OE_ResultStr(OE_Result result)
{
    switch (result)
    {
        case OE_OK:
            return "OE_OK";
        case OE_FAILURE:
            return "OE_FAILURE";
        case OE_BUFFER_TOO_SMALL:
            return "OE_BUFFER_TOO_SMALL";
        case OE_INVALID_PARAMETER:
            return "OE_INVALID_PARAMETER";
        case OE_OUT_OF_MEMORY:
            return "OE_OUT_OF_MEMORY";
        case OE_OUT_OF_STACK:
            return "OE_OUT_OF_STACK";
        case OE_OUT_OF_THREADS:
            return "OE_OUT_OF_THREADS";
        case OE_ECALL_FAILED:
            return "OE_ECALL_FAILED";
        case OE_OCALL_FAILED:
            return "OE_OCALL_FAILED";
        case OE_UNEXPECTED:
            return "OE_UNEXPECTED";
        case OE_VERIFY_FAILED:
            return "OE_VERIFY_FAILED";
        case OE_NOT_FOUND:
            return "OE_NOT_FOUND";
        case OE_INTEGER_OVERFLOW:
            return "OE_INTEGER_OVERFLOW";
        case OE_WRONG_TYPE:
            return "OE_WRONG_TYPE";
        case OE_UNIMPLEMENTED:
            return "OE_UNIMPLEMENTED";
        case OE_OUT_OF_BOUNDS:
            return "OE_OUT_OF_BOUNDS";
        case OE_OVERLAPPED_COPY:
            return "OE_OVERLAPPED_COPY";
        case OE_UNKNOWN_FUNCTION:
            return "OE_UNKNOWN_FUNCTION";
        case OE_FAILED_OPT_CONSTRAINT:
            return "OE_FAILED_OPT_CONSTRAINT";
        case OE_DYNAMIC_LOAD_FAILED:
            return "OE_DYNAMIC_LOAD_FAILED";
        case OE_DYNAMIC_SYMBOL_LOOKUP_FAILED:
            return "OE_DYNAMIC_SYMBOL_LOOKUP_FAILED";
        case OE_BUFFER_OVERRUN:
            return "OE_BUFFER_OVERRUN";
        case OE_BAD_MAGIC:
            return "OE_BAD_MAGIC";
        case OE_IOCTL_FAILED:
            return "OE_IOCTL_FAILED";
        case OE_UNSUPPORTED:
            return "OE_UNSUPPORTED";
        case OE_UNKNOWN_OPTION:
            return "OE_UNKNOWN_OPTION";
        case OE_READ_FAILED:
            return "OE_READ_FAILED";
        case OE_OUT_OF_RANGE:
            return "OE_OUT_OF_RANGE";
        case OE_ALREADY_IN_USE:
            return "OE_ALREADY_IN_USE";
        case OE_SERVICE_UNAVAILABLE:
            return "OE_SERVICE_UNAVAILABLE";
        case OE_ENCLAVE_ABORTING:
            return "OE_ENCLAVE_ABORTING";
        case OE_ENCLAVE_ABORTED:
            return "OE_ENCLAVE_ABORTED";
        case OE_PLATFORM_ERROR:
            return "OE_PLATFORM_ERROR";
    }

    return "UNKNOWN";
}
