#ifndef OE_SAMPLES_ATTESTATION_ARGS_H
#define OE_SAMPLES_ATTESTATION_ARGS_H

#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>

#include "messages.h"

/**
 * Identifier for an enclave.
 */
typedef struct _EnclaveId
{
    const uint8_t* bytes;
    uint32_t length;
} EnclaveId;

struct InitEnclaveArgs {
    EnclaveId enclaveId;
};

struct SendTextMessageArgs {
    EnclaveId toEnclave;

    PlainTextMessage* message;
    OE_Result result;
};

struct ReceiveTextMessageArgs {
    EnclaveId fromEnclave;

    PlainTextMessage* message;
    OE_Result result;
};

struct SendPublicKeyMessageArgs {
    EnclaveId toEnclave;

    PublicKeyMessage* message;
    OE_Result result;
};

struct ReceivePublicKeyMessageArgs {
    EnclaveId fromEnclave;

    PublicKeyMessage* message;
    OE_Result result;
};

struct SendEncryptedMessageArgs {
    EnclaveId toEnclave;

    EncryptedMessage* message;
    OE_Result result;
};

struct ReceiveEncryptedMessageArgs {
    EnclaveId fromEnclave;

    EncryptedMessage* message;
    OE_Result result;
};

#endif // OE_SAMPLES_ATTESTATION_ARGS_H
