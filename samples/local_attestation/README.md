# The Local Attestation Sample

In a typical Open Enclave application, it's common to see multiple enclaves working together to achieve common goals. They would need to attest each other before a trust could be established.
Once an enclave verifies the counterpart is trustworthy, they can exchange information on a protected channel, which typically provides confidentiality, integrity and replay protection.
This sample demonstrates how to conduct local attestation between two enclaves on the same system and establish a secure communication channel for exchanging messages between them.

It has the following properties:

- Written in C++
- Demonstrates an implementation of local attestation
- Use of mbedTLS within the enclave
- Use Asymmetric / Public-Key Encryption to establish secure communications between two attesting enclaves
- Enclave APIs used:
  - oe_get_report
  - oe_verify_report,
  - oe_get_target_info
  
## Attestation primer

See [Remote Attestation's README](../remote_attestation/README.md#attestation-primer) for information

## Local Attestation sample

This sample demonstrates how to attest two enclaves to each other locally by using Open Enclave APIs: `oe_get_report`, `oe_get_target_info`, and `oe_verify_report`. They work together to complete a local attestation process.

To simplify this sample without losing the focus in explaining how the local attestation works, host1 and host2 are combined into one single host to eliminate the need for additional  code for inter-process communication between two hosts.
Diagram 2 is the configuration used in this sample.

![Local Attestation sample](images/localattestation_sample_datails.png)

### Local Attestation steps

For two enclaves on the same system to locally attest each other, the enclaves need to know each other’s identities. OE SDK provides `oe_get_report`, `oe_get_target_info`, and `oe_verify_report` APIs to help broker the identity retrieval, exchange and validation between two enclaves. 

Here are the basic steps of a typical local attestation between two enclaves.

Let's say two enclaves involved are enclave1 and enclave2.

1. Inside enclave1, call `oe_get_report` to get enclave1's report, then call `oe_get_target_info` on enclave1's report
   to get enclave1's target info, enclave1's identity.

2. Send enclave1's identity to enclave2.

3. Inside enclave2, create an **enclave2 report targeted at enclave1**, that is, a report with enclave2's identity
   signed so that enclave1 can verify it.

4. Send the enclave2 report above to enclave1.

5. Inside enclave1, call `oe_verify_report` to verify enclave2 report, on success, it means enclave2 was successfully attested to enclave1.

Step 1-5 completes the process of local attesting enclave2 to enclave1

Repeating step 1-4 with reverse roles of enclave1 and enclave2 can achieve attesting enclave1 to enclave2.

### Authoring the Host

The host application coordinates the local attestation steps described above for helping local attestation process.

The host does the following in this sample:

1. Create two enclaves for attesting each other, let's say they are enclave1 and enclave2

    ```c
    oe_create_localattestation_enclave( enclaveImagePath, OE_ENCLAVE_TYPE_SGX, OE_ENCLAVE_FLAG_DEBUG, NULL, 0, &enclave);
    ```

2.  Attest enclave 1 to enclave 2

    ```c
    attest_one_enclave_to_the_other("enclave1", enclave1, "enclave2", enclave2);
    ```

3. Attest enclave 2 to enclave 1

    ```c
    attest_one_enclave_to_the_other("enclave2", enclave2, "enclave1", enclave1);
    ```

    With successfully attestation on each other, we are ready to securely exchange data between enclaves via asymmetric encryption.

4. Get encrypted message from 1st enclave

    ```c
    generate_encrypted_message(enclave1, &ret, &encrypted_msg, &encrypted_msg_size);
    ```

5. Sending the encrypted message to 2nd enclave to decrypt and validate if the decrypted 
   message is correct.

   Note: both enclaves hardcode their sample messages for this validation.

    ```c
    process_encrypted_msg(enclave2, &ret, encrypted_msg, encrypted_msg_size);
    ```

#### attest_one_enclave_to_the_other() routine

This routine handles the process of attesting enclave2 to enclave1 with the following three steps.

```c
get_target_info(enclave1, &ret, &target_info_buf, &target_info_size);

get_targeted_report_with_pubkey(enclave2, &ret,
                                target_info_buf, target_info_size,
                                &pem_key, &pem_key_size,
                                &report, &report_size);

verify_report_and_set_pubkey(enclave1, &ret, 
                             pem_key,pem_key_size,
                             report, report_size);
```

### Authoring the Enclave

#### Attesting an Enclave

Let's say, we want to attest enclave 2 to enclave 1.

Attesting an enclave consists of three steps:

##### 1) Get an enclave's identity (target info)

To conduct a local attestation, both enclaves need to know each other’s identities.
This is done by calling oe_get_target_info on the enclave 1's own report.

```c
oe_result_t oe_get_target_info(
    const uint8_t* report,
    size_t report_size,
    void* target_info_buffer,
    size_t* target_info_size);
```

On a successful return, target_info_buffer will be deposited with platform specific identity information needed for local attestation.

##### 2) Generate a targeted report with the other enclave's target info (identity)

Inside enclave 2, call oe_get_report with the target info as opt_params. This creates a enclave2 report that' targeted at enclave 1, 
that is, for enclave 1 to validate.

```c
oe_result_t oe_get_report(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report_buffer,
    size_t* report_buffer_size);
```

##### 3) Verify targeted report

This validation consists two parts:

1. Integrity of the Enclave Report

    Enclave 1 can call `oe_verify_report` to validate the report originated from an Trust Execution Environment (TEE),
    which in this case would be a valid SGX platform.

    ```c
    oe_result_t oe_verify_report(const uint8_t* report, size_t report_size, oe_report_t* parsed_report);
    ```

    At this point, Enclave 1 knows that the report originated from an enclave running in a TEE, and that the information in the report can be trusted.

1. Validation of an enclave identity

    Finally, **it is up to the enclave app to check that identity and properties of the enclave reflected in the report matches its expectation**.
    Open Enclave exposes a generalized identity model to support this process across TEE types. `oe_identity_t` is the data structure that defined for this 
    identity model.

    ```c
    typedef struct _oe_identity
    {
        /** Version of the oe_identity_t structure */
        uint32_t idVersion;

        /** Security version of the enclave. For SGX enclaves, this is the
         *  ISVN value */
        uint32_t securityVersion;

        /** Values of the attributes flags for the enclave -
         *  OE_REPORT_ATTRIBUTES_DEBUG: The report is for a debug enclave.
         *  OE_REPORT_ATTRIBUTES_REMOTE: The report can be used for remote
         *  attestation */
        uint64_t attributes;

        /** The unique ID for the enclave.
         * For SGX enclaves, this is the MRENCLAVE value */
        uint8_t uniqueID[OE_UNIQUE_ID_SIZE];

        /** The author ID for the enclave.
         * For SGX enclaves, this is the MRSIGNER value */
        uint8_t authorID[OE_AUTHOR_ID_SIZE];

        /** The Product ID for the enclave.
         * For SGX enclaves, this is the ISVPRODID value. */
        uint8_t productID[OE_PRODUCT_ID_SIZE];
    } oe_identity_t;
    ```

    As shown in the sample, the set of validations performed on these properties is up to the app.

    In general, we would strongly recommend:

    - Ensure that the identity of the enclave matches the expected value:
    - Verify the `uniqueID` value if you want to match the exact bitwise identity of the enclave. Bear in mind that any patches to the enclave will change the uniqueID in the future.
    - Verify the `authorID` and `productID` values if you want to match the identity of an enclave that might span multiple binary versions. This is what the attestation sample does.
    - Ensure that the `securityVersion` of the enclave matches your minimum required security version.
    - Ensure that the `reportData` matches the hash of the data provided with the report, as illustrated by the sample.

    In the sample, the app-specific `Attestation::attest_local_report` method calls `oe_parse_report` to obtain an `oe_report_t`
    for report integrity checking before conducting enclave identity validation based on the information inside `parsed_report`.

## Using Cryptography in an Enclave

The attestation `local_attestation/common/crypto.cpp` file from the sample illustrates how to use mbedTLS inside the enclave for cryptographic operations such as:

- RSA key generation, encryption and decryption
- SHA256 hashing

In general, the Open Enclave SDK provides default support for mbedTLS layered on top of the Open Enclave core runtime with a small integration surface so that it can be switched out by open source developers in the future for your choice of crypto libraries.

See [here](https://github.com/Microsoft/openenclave/tree/master/docs/MbedtlsSupport.md) for supported mbedTLS functions

## Build and run

Note that there are two different build systems supported, one using GNU Make and
`pkg-config`, the other using CMake.

### CMake

This uses the CMake package provided by the Open Enclave SDK.

```bash
cd local_attestation
mkdir build && cd build
cmake ..
make run
```

### GNU Make

```bash
cd local_attestation
make build
make run
```
