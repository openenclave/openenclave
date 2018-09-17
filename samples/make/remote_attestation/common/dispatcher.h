// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include <openenclave/enclave.h>
#include <string>
#include "../args.h"
#include "attestation.h"
#include "crypto.h"

using namespace std;

typedef struct _enclave_config_data
{
    uint8_t* enclave_secret_data;
    uint8_t* enclave_mr_signer;
} EnclaveConfigData;

class EcallDispatcher
{
  private:
    bool m_initialized;
    Crypto* m_p_crypto;
    Attestation* m_attestation;
    string m_name;
    EnclaveConfigData* m_enclave_config;

  public:
    EcallDispatcher(const char* name, EnclaveConfigData* enclave_config);
    ~EcallDispatcher();
    void GetRemoteReportWithPublicKey(GetRemoteReportWithPubKeyArgs* arg);
    void VerifyReportAndSetKey(VerifyReportWithPubKeyArgs* arg);
    void GenerateEncryptedData(GenerateEncryptedMessageArgs* arg);
    void ProcessEncryptedData(ProcessEncryptedMessageArgs* arg);

  private:
    bool initialize(const char* name);
};
