// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include <openenclave/enclave.h>
#include <string>
#include "../args.h"
#include "attestation.h"
#include "crypto.h"

using namespace std;

typedef struct _EnclaveConfigData
{
    uint8_t* enclaveSecretData;
    uint8_t* enclaveMRSigner;
} EnclaveConfigData;

class EcallDispatcher
{
  private:
    bool m_Initialized;
    Crypto* m_pCrypto;
    Attestation* m_attestation;
    string m_name;
    EnclaveConfigData* m_EnclaveConfig;

  public:
    EcallDispatcher(const char* name, EnclaveConfigData* enclaveConfig);
    ~EcallDispatcher();
    void GetRemoteReportWithPublicKey(GetRemoteReportWithPubKeyArgs* arg);
    void VerifyReportAndSetKey(VerifyReportWithPubKeyArgs* arg);
    void GenerateEncryptedData(GenerateEncryptedMessageArgs* arg);
    void ProcessEncryptedData(ProcessEncryptedMessageArgs* arg);

  private:
    bool initialize(const char* name);
};
