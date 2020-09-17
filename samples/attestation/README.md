# The Attestation Sample

This sample demonstrates how to do attestation between two enclaves and establish a secure communication channel for exchanging messages between them.

It has the following properties:

- Written in C++
- Demonstrates an implementation of attestation
- Use of mbedTLS within the enclave
- Use Asymmetric / Public-Key Encryption to establish secure communications between two attesting enclaves
- Enclave APIs used:
  - `oe_verifier_initialize()`
  - `oe_attester_initialize()`
  - `oe_serialize_custom_claims()`
  - `oe_deserialize_custom_claims()`
  - `oe_get_evidence()`
  - `oe_verify_evidence()`
  - `oe_verifier_get_format_settings()`
  - `oe_is_within_enclave()`

**Note: Unlike the local SGX functionality, currently the remote SGX functionality only works on SGX-FLC systems.** The underlying SGX library support for end-to-end remote attestation is available only on SGX-FLC systems. There is no plan to back port those libraries to either an SGX1 system or simulation mode.

## Attestation primer

### What is Attestation

Attestation is the process of demonstrating that a software component (such as an enclave image) has been properly instantiated on a Trusted Execution Environment (TEE, such as the SGX enabled platform).

A successfully attested enclave proves:

- The enclave is running in a valid Trusted Execution Environment (TEE), which is Intel SGX in this case (trustworthiness).

- The enclave has the correct identity and runtime properties that have not been tampered with (identity).

In the context of Open Enclave, when an enclave requests confidential information from a remote entity, the remote entity will issue a challenge to the requesting enclave to prove its identity and trustworthiness before provisioning any confidential information to the enclave. This process of proving its identity and trustworthiness to a challenger is known as attestation.

### Attestation types

Most TEEs use one attestation mechanism specific to that TEE.
SGX, however, has two separate mechanisms for local vs. remote attestation:

- **Local Attestation** refers to two enclaves on the same TEE platform establishing trust in each other before exchanging information. In Open Enclave, this is done through the creation and validation of an enclave's "Intel SGX report".

  ![Local Attestation](images/localattestation.png)

- **Remote Attestation** is the process of a [trusted computing base (TCB)](https://en.wikipedia.org/wiki/Trusted_computing_base), a combination of HW and SW, gaining the trust of a remote enclave/provider. In Open Enclave, this is done through the creation and validation of an enclave's "Intel SGX quote".

  ![Remote Attestation Sample](images/remoteattestation_service.png)

For more details on attestation in SGX, see the [Intel SGX attestation](
https://software.intel.com/sites/default/files/managed/57/0e/ww10-2016-sgx-provisioning-and-attestation-final.pdf)
article.

### Secure Communication Channel

Attestation alone is not enough for a peer to be able to securely deliver secrets to a requesting enclave. Securely delivering secrets requires a secure communication channel which is often guaranteed by Transport Layer Security (TLS).

A few alternatives for establishing a secure communication channel without TLS are:
1) Use the established ephemeral private keys to perform a signed Diffie-Hellman key exchange and use symmetric key cryptography to communicate after that point.
2) Generate an ephemeral symmetric key in one of the enclaves, say enclave_a, encrypt with the public key of enclave_b, sign with your private key and then send it to enclave_b. This will ensure that the symmetric key is only known to the two enclaves and the root of trust is in the remote attestation.

This remote attestation sample only demonstrates the remote attestation process but does not establish a secure communication channel or communicate secrets after that. Please note that the established public keys cannot be used to encrypt the messages as they are visible to the external world, including the host. The host can fake messages on behalf of the enclaves.

## Attestation sample

In a typical Open Enclave application, it's common to see multiple enclaves working together to achieve common goals. Once an enclave verifies the counterpart is trustworthy, they can exchange information on a protected channel, which typically provides confidentiality, integrity and replay protection.

This is why instead of attesting an enclave to a remote (mostly cloud) service, this sample demonstrates how to attest two enclaves to each other by using Open Enclave APIs `oe_verifier_get_format_settings()`, `oe_get_evidence()`, and `oe_verify_evidence()` which take care of all attestation operations.

To simplify this sample without losing the focus in explaining how the attestation works, host1 and host2 are combined into one single host to eliminate the need for additional socket code logic to deal with communication between two hosts.

Local Attestation:
![Local Attestation sample](images/localattestation_sample_datails.png)

Remote Attestation:
![Remote Attestation](images/remoteattestation_sample.png)

### Authoring the Host

The host process is what drives the enclave app. It is responsible for managing the lifetime of the enclave and invoking enclave ECALLs but should be considered an untrusted component that is never allowed to handle plaintext secrets intended for the enclave.

![Remote Attestation](images/remoteattestation_sample_details.png)

The host does the following in this sample:

   1. Create two enclaves for attesting each other, let's say they are enclave_a and enclave_b

      ```c
      oe_create_attestation_enclave( enclaveImagePath, OE_ENCLAVE_TYPE_AUTO, OE_ENCLAVE_FLAG_DEBUG, NULL, 0, &enclave);
      ```

   2. Ask enclave_a for evidence and a public key:

      This is done through a call into the enclave_a `get_evidence_with_public_key()` `OE_ECALL`

      ```c
      get_evidence_with_public_key(enclave_a,
                                   &ret,
                                   format_id,
                                   format_settings,
                                   format_settings_size,
                                   &pem_key,
                                   &pem_key_size,
                                   &evidence,
                                   &evidence_size);
      ```

      Where:

        - `pem_key` holds the public key that identifies enclave_a, and

        - `evidence` contains the evidence signed by the enclave platform for use in remote attestation.

   3. Ask enclave_b to attest (validate) enclave_a's evidence.

      This is done through the following call:
      ```c
      verify_evidence_and_set_public_key(enclave_a,
                                         &ret,
                                         format_id,
                                         pem_key,
                                         pem_key_size,
                                         evidence,
                                         evidence_size);
      ```

      In the enclave_b's implementation of `verify_evidence_and_set_public_key()`, it calls `oe_verify_evidence()`, which will be described in the enclave section to handle all the platform-specfic evidence validation operations. If successful the public key in `pem_key` will be stored inside the enclave for future use.

   4. Repeat steps 2 and 3 for asking enclave\_a to validate enclave\_b.

   5. Ask enclave\_a to generate a message encrypted with enclave\b's public key.

      ```c
      generate_encrypted_message(enclave_a, &ret, &encrypted_message, &encrypted_message_size);
      ```

   6. Send the encrypted message to enclave\_b to decrypt and validate if the decrypted
      message is correct.

      ```c
      process_encrypted_message(enclave_b, &ret, encrypted_message, encrypted_message_size);
      ```

   7. Free any resources used, including the enclaves themselves.

      For example:

      ```c
      oe_terminate_enclave(enclave_a);
      oe_terminate_enclave(enclave_b);
      ```

### Authoring the Enclave

For two enclaves to mutually attest to each other, each enclave needs
to separately attest to the other.  This sample illustrates both
enclaves doing so using the same procedure.

#### Attesting an Enclave

Let's say, we want to attest enclave 2 (the "Attester")
to enclave 1 (the "Verifier").

Attesting an enclave consists of three steps:

##### 1) Get a challenge from the Verifier

To conduct an attestation and ensure that the evidence is fresh,
the Verifier (enclave 1) needs to be able to construct a challenge that it
expects to be used when the Attester (enclave 2) generates its evidence.
(In SGX local attestation, the challenge also contains the identity
of the Verifier.)
This is done by calling `oe_verifier_get_format_settings()` from the Verifier enclave,
where the `format_id` identifies the attestation mechanism (e.g., SGX
local attestation vs SGX remote attestation).

```
oe_result_t oe_verifier_get_format_settings(
    const oe_uuid_t* format_id,
    uint8_t** settings,
    size_t* settings_size);
```

##### 2) Generate evidence from the Attester enclave

Using the challenge provided by the Verifier, the Attester enclave needs to
generate cryptographically strong evidence
of its trustworthiness that the Verifier can appraise. In the sample this is
done by asking the platform to generate such evidence.

An important feature of `oe_get_evidence()` is that you can pass in application specific data as the `custom_claims_buffer` parameter to be signed into the evidence.

- This is limited to 64 bytes in SGX. As illustrated in the sample, you sign arbitrarily large data into the evidence by first hashing it and then passing it to the `oe_get_evidence()` method.

- This is useful to bootstrap a secure communication channel between the enclave and the challenger.

  - In this sample, the enclave signs the hash of an ephemeral public key into its evidence, which the challenger can then use to encrypt a response to it.

  - Other usage examples for `custom_claims_buffer` might be to include a nonce, or to initiate a Diffie-Helman key exchange.

##### 3) Verifying the integrity of the evidence

Once the evidence is generated and passed to the Verifier, the Verifier can
call `oe_verify_evidence()` to validate the evidence.

For Intel SGX remote attestation for example, an Intel SGX quote is verified using the certificate chain issued by Intel which is only valid for SGX platforms.
Note: Currently, remote attestation verification is only supported in Azure ACC VMs, but Intel will be expanding support for this with Open Enclave SDK more broadly moving forward.

At this point, the challenger knows that the evidence originated from an enclave running in a TEE, and that the information in the evidence can be trusted.

##### 4) Verifying the Attester enclave identity

This validation consists two parts:

1. Verifying the integrity of the evidence

    Enclave 1 can call `oe_verify_evidence()` to validate the evidence originated
    from an Trusted Execution Environment (TEE).

    ```c
    oe_result_t oe_verify_evidence(
        const oe_uuid_t* format_id,
        const uint8_t* evidence_buffer,
        size_t evidence_buffer_size,
        const uint8_t* endorsements_buffer,
        size_t endorsements_buffer_size,
        const oe_policy_t* policies,
        size_t policies_size,
        oe_claim_t** claims,
        size_t* claims_length);
    ```

    At this point, Enclave 1 knows that the evidence originated from an enclave running in a TEE, and that the information in the evidence can be trusted.

2. Establish trust in the Attester enclave

To establish trust in the enclave that generated the evidence,
the Signer ID, Product ID, and Security Version values are
checked to see if they are predefined trusted values.
Once the enclave's trust has been established, the validity of
any accompanying data is ensured by comparing its SHA256 digest
against the hash value stored in a custom claim in the signed evidence.

As shown in the sample, the set of validations performed on these properties is up to the app. In general, we would strongly recommend:

* Ensure that the identity of the enclave matches the expected value:
  - Verify the `OE_CLAIM_UNIQUE_ID` value if you want to match the exact bitwise identity of the enclave. Bear in mind that any patches to the enclave will change the `unique_id` claim in the future.
  - Verify the `OE_CLAIM_SIGNER_ID` and `OE_CLAIM_PRODUCT_ID` values if you want to match the identity of an enclave that might span multiple binary versions. This is what the attestation sample does.
* Ensure that the `OE_CLAIM_SECURITY_VERSION` value of the enclave matches your minimum required security version.
* Ensure that the hash encoded in the `OE_CLAIM_CUSTOM_CLAIMS_BUFFER` claim matches the hash of any accompanying data, as illustrated by the sample.

## Using Cryptography in an Enclave

The `attestation/common/crypto.cpp` file from the sample illustrates how to use mbedTLS inside the enclave for cryptographic operations such as:

- RSA key generation, encryption and decryption
- SHA256 hashing

In general, the Open Enclave SDK provides default support for mbedTLS layered on top of the Open Enclave core runtime with a small integration surface so that it can be switched out by open source developers in the future for your choice of crypto libraries.

See [here](https://github.com/openenclave/openenclave/tree/master/docs/MbedtlsSupport.md) for supported mbedTLS functions

## Build and run

In order to build and run this sample, please refer to the common sample [README file](../README.md#building-the-samples).

To use only the SGX local functionality:

* On Linux, use `make runsgxlocal` instead of `make run`.

* On Windows, use `ninja runsgxlocal` instead of `ninja run`.

To use only the SGX remote functionality:

* On Linux, use `make runsgxremote` instead of `make run`.

* On Windows, use `ninja runsgxremote` instead of `ninja run`.
