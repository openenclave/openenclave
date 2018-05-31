// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <map>


#include <openenclave/oe-mbedtls/mbedtls/config.h>
#include <openenclave/oe-mbedtls/mbedtls/ctr_drbg.h>
#include <openenclave/oe-mbedtls/mbedtls/entropy.h>
#include <openenclave/oe-mbedtls/mbedtls/pk.h>
#include <openenclave/oe-mbedtls/mbedtls/rsa.h>
#include <openenclave/oe-mbedtls/mbedtls/sha256.h>


#include "../args.h"


bool GenerateQuoteForData(uint8_t* data, uint32_t size, uint8_t* quote, uint32_t* quoteSize)
{
    uint8_t quoteBuffer[OE_MAX_REPORT_SIZE];    
    uint8_t sha256[32] = {0};
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, data, size);
    mbedtls_sha256_finish(&ctx, sha256);

    *quoteSize = sizeof(quoteBuffer);
    if(OE_GetReport(
            OE_REPORT_OPTIONS_REMOTE_ATTESTATION, 
            sha256, sizeof(sha256),
            NULL, 0,
            quoteBuffer,
            quoteSize) == OE_OK)
    {
        memcpy(quote, quoteBuffer, *quoteSize);
        return true;
    }

    return false;
} 

bool VerifyQuoteForData(uint8_t* data, uint32_t size, uint8_t* quote, uint32_t quoteSize)
{
    uint8_t quoteBuffer[OE_MAX_REPORT_SIZE];
    uint8_t sha256[32] = {0};
    mbedtls_sha256_context ctx;
    OE_Report parsedReport;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, data, size);
    mbedtls_sha256_finish(&ctx, sha256);

    memcpy(quoteBuffer, quote, quoteSize);
    if (OE_VerifyReport(quoteBuffer, quoteSize, &parsedReport) == OE_OK) {
        // Todo: Verify mrsigner and mrenclave values to ensure this is an enclave trusted by current enclave.

        return memcmp(sha256, parsedReport.reportData, sizeof(sha256)) == 0;
    }

    return false;
}


std::string myEnclaveId = "uninitialized-enclave";

OE_ECALL void InitializeEnclave(void* args_)
{
    InitEnclaveArgs args, *argsPtr;

    argsPtr = (InitEnclaveArgs*)args_;
    if (!argsPtr || !OE_IsOutsideEnclave(argsPtr, sizeof(*argsPtr)))
        return;

    args = *argsPtr;
    myEnclaveId = std::string(args.enclaveId.bytes, args.enclaveId.bytes+args.enclaveId.length)  + ":enclave";
}

void HostPrintf ( const char * format, ... )
{
  static char buffer[4*1024];
  static OE_Spinlock lock = OE_SPINLOCK_INITIALIZER;
  OE_SpinLock(&lock);

  va_list args;
  va_start (args, format);
  vsnprintf (buffer,256,format, args);
  va_end (args);
  OE_HostPrintf("%s", buffer);

  OE_SpinUnlock(&lock);
}


OE_ECALL void SendTextMessage(void* args_)
{
    SendTextMessageArgs args, *argsPtr;    
    uint8_t text[512] = {0};    
    uint8_t quote[OE_MAX_REPORT_SIZE];
    uint32_t quoteSize = 0;

    argsPtr = (SendTextMessageArgs*)args_;
    if (!argsPtr || !OE_IsOutsideEnclave(argsPtr, sizeof(*argsPtr)))
        return;
    
    args = *argsPtr;
    sprintf((char*)text, "Hello %*s!", args.toEnclave.length, args.toEnclave.bytes);
    
    if (GenerateQuoteForData(text, sizeof(text), quote, &quoteSize)) {
        PlainTextMessage* msg = (PlainTextMessage*) OE_HostMalloc(sizeof(PlainTextMessage) + quoteSize);
        memcpy(msg->text, text, 512);
        msg->quoteSize = quoteSize;
        memcpy(msg->quote, quote, quoteSize);

        HostPrintf("||%s: Sending '%s' to %*s. Quoted.\n", myEnclaveId.c_str(), text, args.toEnclave.length, args.toEnclave.bytes);
        argsPtr->message = msg;
        argsPtr->result = OE_OK;    
    } else {
        HostPrintf("||%s: Failed to generate message for %*s.\n", myEnclaveId.c_str(), args.toEnclave.length, args.toEnclave.bytes);
        argsPtr->result = OE_FAILURE;
    }
}

OE_ECALL void ReceiveTextMessage(void* args_)
{
    ReceiveTextMessageArgs args, *argsPtr;    
    
    argsPtr = (ReceiveTextMessageArgs*)args_;
    if (!argsPtr || !OE_IsOutsideEnclave(argsPtr, sizeof(*argsPtr)))
        return;

    args = *argsPtr;

    uint32_t quoteSize = args.message->quoteSize;
    PlainTextMessage* msg = (PlainTextMessage*) malloc(sizeof(PlainTextMessage) + quoteSize);
    memcpy(msg, args.message, quoteSize + sizeof(PlainTextMessage));
    
    if (VerifyQuoteForData((uint8_t*)msg->text, sizeof(msg->text), msg->quote, msg->quoteSize)) {
        HostPrintf("||%s: Received '%s' from %*s. Validated.\n", myEnclaveId.c_str(), msg->text, args.fromEnclave.length, args.fromEnclave.bytes);
        argsPtr->result = OE_OK;
    } else {
        HostPrintf("||%s: Failed to authenticate message from %*s.\n", myEnclaveId.c_str(), args.fromEnclave.length, args.fromEnclave.bytes);
        argsPtr->result = OE_FAILURE;
    }

    free(msg);
}

struct Key {
    //mbedtls_rsa_context ctx;
    mbedtls_pk_context key;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    bool initialized;

    Key() : initialized(false) {}
};

std::map<std::string, Key> myKeys;
std::map<std::string, Key> theirKeys;

void GenerateKey(const std::string& enclaveId)
{
    Key& key = myKeys[enclaveId];
    
    if (!key.initialized) {       
        mbedtls_ctr_drbg_init( &key.ctr_drbg );
        mbedtls_entropy_init(&key.entropy);
        mbedtls_pk_init( &key.key );

        int res = mbedtls_ctr_drbg_seed(&key.ctr_drbg, mbedtls_entropy_func, &key.entropy, NULL, 0);
         
        if (res != 0) {
             HostPrintf("||%s: mbedtls_ctr_drbg_seed failed\n", myEnclaveId.c_str());  
             return;           
        }

        res = mbedtls_pk_setup( &key.key, mbedtls_pk_info_from_type( MBEDTLS_PK_RSA));         
        if (res != 0) {
             HostPrintf("||%s: mbedtls_pk_setup failed\n", myEnclaveId.c_str());  
             return;           
        }
       
        res  = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key.key), mbedtls_ctr_drbg_random, &key.ctr_drbg,
                            2048, 65537 );
        if (res != 0) {
            HostPrintf("||%s: mbedtls_rsa_gen_key Initialized\n",myEnclaveId.c_str());
            return;
        } 

        key.initialized = true;
        HostPrintf("||%s: RSA Key generated for %s\n", myEnclaveId.c_str(), enclaveId.c_str());
    }
}

void ReadPublicKey(const std::string& enclaveId, const uint8_t* buf, uint32_t size)
{
    Key& key = theirKeys[enclaveId];
    
    if (!key.initialized) {
        mbedtls_ctr_drbg_init( &key.ctr_drbg );
        mbedtls_entropy_init(&key.entropy);
        mbedtls_pk_init( &key.key );

        int res = mbedtls_ctr_drbg_seed(&key.ctr_drbg, mbedtls_entropy_func, &key.entropy, NULL, 0);
         
        if (res != 0) {
             HostPrintf("||%s: mbedtls_ctr_drbg_seed failed\n", myEnclaveId.c_str());  
             return;           
        }

        mbedtls_pk_init( &key.key );
        size = strlen((const char*)buf) + 1;
        res = mbedtls_pk_parse_public_key(&key.key, buf, size);
        if (res == 0) {
            HostPrintf("||%s: Public Key parsed successfully for %s\n", myEnclaveId.c_str(), enclaveId.c_str());
            key.initialized = true;
        } else {
            HostPrintf("||%s: mbedtls_pk_parse_public_key failed.\n", myEnclaveId.c_str());  
        }
    }    
}

void EncryptDataFor(const std::string& enclaveId, const uint8_t* data, uint32_t size, uint8_t* buffer, uint32_t* bufferSize)
{
    Key& key = theirKeys[enclaveId];
    if (key.initialized) {

        int ret = mbedtls_rsa_pkcs1_encrypt( mbedtls_pk_rsa(key.key), mbedtls_ctr_drbg_random,
                                            &key.ctr_drbg, MBEDTLS_RSA_PUBLIC,
                                            size, data, buffer );
        if (ret == 0) {
            *bufferSize = mbedtls_pk_rsa(key.key)->len;
            HostPrintf("||%s: mbedtls_rsa_pkcs1_encrypt succeeded. size=%d bytes.\n", myEnclaveId.c_str(), *bufferSize);  
        } else {
            HostPrintf("||%s: mbedtls_rsa_pkcs1_encrypt failed.\n", myEnclaveId.c_str());  
        }

    } else {
        HostPrintf("||%s: No public key found for %s.\n", myEnclaveId.c_str(), enclaveId.c_str());
    }
}

void DecryptDataFrom(const std::string& enclaveId, const uint8_t* encryptedData, uint32_t encryptedDataSize, uint8_t* buffer, uint32_t* bufferSize)
{
    Key& key = myKeys[enclaveId];
    if (key.initialized) {
        size_t outputSize = *bufferSize;
        mbedtls_pk_rsa(key.key)->len = encryptedDataSize;
        int ret = mbedtls_rsa_pkcs1_decrypt( mbedtls_pk_rsa(key.key), mbedtls_ctr_drbg_random,
                                            &key.ctr_drbg, MBEDTLS_RSA_PRIVATE,
                                            &outputSize, encryptedData, buffer, outputSize);
        if (ret == 0) {
            *bufferSize = outputSize;
            HostPrintf("||%s: mbedtls_rsa_pkcs1_decrypt succeeded. size=%d bytes.\n", myEnclaveId.c_str(), outputSize);  
        } else {
            HostPrintf("||%s: mbedtls_rsa_pkcs1_decrypt failed.\n", myEnclaveId.c_str());  
        }

    } else {
        HostPrintf("||%s: No public key generated for talking to %s.\n", myEnclaveId.c_str(), enclaveId.c_str());
    }
}


OE_ECALL void SendPublicKeyMessage(void* args_)
{
    SendPublicKeyMessageArgs args, *argsPtr;    
    uint8_t keyBuf[512] = {0};
    uint8_t quote[OE_MAX_REPORT_SIZE];
    uint32_t quoteSize = 0;

    argsPtr = (SendPublicKeyMessageArgs*)args_;
    if (!argsPtr || !OE_IsOutsideEnclave(argsPtr, sizeof(*argsPtr)))
        return;
    
    args = *argsPtr;
    std::string enclaveId(args.toEnclave.bytes, args.toEnclave.bytes+ args.toEnclave.length);

    GenerateKey(enclaveId);
    Key& key = myKeys[enclaveId];
    
    argsPtr->result = OE_FAILURE;
    if (key.initialized) {
        if (mbedtls_pk_write_pubkey_pem(&key.key, keyBuf, sizeof(keyBuf)) == 0) {
            int keyLength = strlen((char*)keyBuf);
            HostPrintf("||%s: mbedtls_pk_write_pubkey_pem succeeded. Length = %d bytes. \n", myEnclaveId.c_str(), keyLength);            
            HostPrintf("%*s",  keyLength, keyBuf);
            HostPrintf("\n");
            if (GenerateQuoteForData(keyBuf, sizeof(keyBuf), quote, &quoteSize)) {
                PublicKeyMessage* msg = (PublicKeyMessage*) OE_HostMalloc(sizeof(PublicKeyMessage) + quoteSize);
                memcpy(msg->publicKey, keyBuf, sizeof(keyBuf));
                msg->quoteSize = quoteSize;
                memcpy(msg->quote, quote, quoteSize);

                HostPrintf("||%s: Sending Public Key to %*s. Quoted.\n", myEnclaveId.c_str(), args.toEnclave.length, args.toEnclave.bytes);
                argsPtr->message = msg;
                argsPtr->result = OE_OK;                              
            } else {
                HostPrintf("||%s: Failed to generate key message for %*s.\n", myEnclaveId.c_str(), args.toEnclave.length, args.toEnclave.bytes);
            }
        } else {
            HostPrintf("||%s: mbedtls_pk_write_pubkey_pem failed\n", myEnclaveId.c_str());   
        }
    }    
}

OE_ECALL void ReceivePublicKeyMessage(void* args_)
{
    ReceivePublicKeyMessageArgs args, *argsPtr;    
    
    argsPtr = (ReceivePublicKeyMessageArgs*)args_;
    if (!argsPtr || !OE_IsOutsideEnclave(argsPtr, sizeof(*argsPtr)))
        return;

    args = *argsPtr;

    uint32_t quoteSize = args.message->quoteSize;
    PublicKeyMessage* msg = (PublicKeyMessage*) malloc(sizeof(PublicKeyMessage) + quoteSize);
    memcpy(msg, args.message, quoteSize + sizeof(PlainTextMessage));
    
    std::string otherEnclaveId(args.fromEnclave.bytes, args.fromEnclave.bytes + args.fromEnclave.length);
    if (VerifyQuoteForData((uint8_t*)msg->publicKey, sizeof(msg->publicKey), msg->quote, msg->quoteSize)) {
        HostPrintf("||%s: Received Public Key from %s. Validated.\n", myEnclaveId.c_str(), otherEnclaveId.c_str());
        HostPrintf("%*s",  sizeof(msg->publicKey), msg->publicKey);
        HostPrintf("\n");

        ReadPublicKey(otherEnclaveId, msg->publicKey, sizeof(msg->publicKey));
        if (theirKeys[otherEnclaveId].initialized)               
            argsPtr->result = OE_OK;
    } else {
        HostPrintf("||%s: Failed to authenticate Public Key from %*s.\n", myEnclaveId.c_str(), args.fromEnclave.length, args.fromEnclave.bytes);
        argsPtr->result = OE_FAILURE;
    }

    free(msg);
}


OE_ECALL void SendEncryptedMessage(void* args_)
{
    SendEncryptedMessageArgs args, *argsPtr;    
    
    argsPtr = (SendEncryptedMessageArgs*)args_;
    if (!argsPtr || !OE_IsOutsideEnclave(argsPtr, sizeof(*argsPtr)))
        return;
    
    args = *argsPtr;
    std::string enclaveId(args.toEnclave.bytes, args.toEnclave.bytes+ args.toEnclave.length);

    Key& key = myKeys[enclaveId];
    
    argsPtr->result = OE_FAILURE;
    if (key.initialized) {
        uint8_t text[256];
        uint8_t buffer[2*1024];
        uint32_t encryptedSize = 0;

        uint32_t size = 0;
        if (myEnclaveId.find("8000") != myEnclaveId.npos)
            size = sprintf((char*)text, "Call me ASAP!!!") + 1;
        else
            size = sprintf((char*)text, "What is going on???") + 1;

        EncryptDataFor(enclaveId, text, size, buffer, &encryptedSize);
        
        EncryptedMessage* msg = (EncryptedMessage*) OE_HostMalloc(sizeof(EncryptedMessage) + encryptedSize);
        msg->size = encryptedSize;
        memcpy(msg->data, buffer, encryptedSize);

        HostPrintf("||%s: Sending Encrypted message to %s. size=%d bytes.\n", myEnclaveId.c_str(), enclaveId.c_str(), encryptedSize);

        argsPtr->message = msg;
        argsPtr->result = OE_OK;        
    }   
}

OE_ECALL void ReceiveEncryptedMessage(void* args_)
{
    ReceiveEncryptedMessageArgs args, *argsPtr;    
    
    argsPtr = (ReceiveEncryptedMessageArgs*)args_;
    if (!argsPtr || !OE_IsOutsideEnclave(argsPtr, sizeof(*argsPtr)))
        return;
    
    args = *argsPtr;
    std::string enclaveId(args.fromEnclave.bytes, args.fromEnclave.bytes+ args.fromEnclave.length);
    uint32_t msgSize = args.message->size;
    EncryptedMessage* msg = (EncryptedMessage*) malloc(sizeof(EncryptedMessage) + msgSize);
    memcpy(msg, args.message, sizeof(EncryptedMessage) + msgSize);
    msg->size = msgSize;

    Key& key = myKeys[enclaveId];
    
    argsPtr->result = OE_FAILURE;
    if (key.initialized) {
        uint8_t buffer[2*1024];
        uint32_t size = sizeof(buffer);

        DecryptDataFrom(enclaveId, msg->data, msg->size, buffer, & size);
        HostPrintf("||%s: Message from %s decrypted: \n\t'%s'\n", myEnclaveId.c_str(), enclaveId.c_str(), buffer);
        argsPtr->result = OE_OK;        
    }   

    free(msg);
}


