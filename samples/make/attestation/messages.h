#ifndef OE_SAMPLES_ATTESTATION_MESSAGES_H
#define OE_SAMPLES_ATTESTATION_MESSAGES_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

struct PlainTextMessage {
    char text[512];

    uint32_t quoteSize;
    uint8_t quote[];
};

struct PublicKeyMessage {
    uint8_t publicKey[512];

    uint32_t quoteSize;
    uint8_t quote[];
};

struct EncryptedMessage {
    uint32_t size;
    uint8_t data[];
};

#endif // OE_SAMPLES_ATTESTATION_MESSAGES_H
