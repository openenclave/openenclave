# Data-sealing Sample

This sample demonstrates how to perform data sealing and unsealing.

It has the following properties:

- Explain the concept of sealing and unsealing in the OE
- Demonstrate how to use OE sealing APIs
- Use OE APIs
  - `oe_get_seal_key_by_policy`
  - `oe_get_seal_key`

## Data Sealing Primer

The *states of an enclave* are not persisted by a system, that is, when an enclave is destroyed, all of its states are lost. This could happen when an enclave application exits, when a system reboots, or simply when a system goes into deep sleep states. To preserve an enclave's states, those states information must explicitly be sent outside the enclave to some persistent storage. When the same enclave is brought back, its states could be restored from the persistent storage. Some data-sealing is more for caching purpose.

The exact definition of an enclave's states is up to a host app and those enclaves involved. It could be some information about the current processing stage in a data pipeline or as simple as some internal secret.

Before those states information leaves an enclave, they are encrypted to protect it from an untrusted host. **Data Sealing** is the process of *encrypting* enclave's states for persistent storage outside of an enclave. This encrypted states are called *sealed data*. This encryption is performed using a private *seal key*, which is derived from the TEE system an enclave is running on. On the other hand, **Data Unsealing** is the reverse process that decrypts an enclave's sealed data using the same seal key. This allows an enclave's states to be restored when the same enclave was subsequently brought back up.

## How OE supports Data Sealing

Instead of publishing convenient APIs, such as Intel SGX SDK's  [sgx_seal_data](https://software.intel.com/en-us/sgx-sdk-dev-reference-sgx-seal-data) and [sgx_unseal_data](https://software.intel.com/en-us/sgx-sdk-dev-reference-sgx-unseal-data), which uses a pre-determined fixed encryption algorithm(AES-GCM) for encryption, OE decides to only provide generic routine for getting seal key and leaves the encryption algorithm up to the enclave developers to choose whatever algorithm they see fit.

### Seal Key Types

Two type of seal keys are supported by OE: In the OE terminology, each seal key type is called a seal policy.

- `OE_SEAL_POLICY_UNIQUE`

  This type of seal key is derived from a measurement of the enclave. Under this policy, the sealed secret can only be unsealed by an instance of the exact enclave code that sealed it. This policy corresponds to using the SGX MRENCLAVE identity for deriving the sealing key.

- `OE_SEAL_POLICY_PRODUCT`

  This type of seal key is derived from the signer of the enclave. Under this policy,  the sealed secret can be unsealed by any enclave signed by the same signer as that of the sealing enclave. The "PRODUCT" in the policy name assumes all enclaves signed by the same signer belong to the same product. This policy corresponds to using the SGX MRSIGNER and ISVPRODID values for deriving the sealing key.

### OE APIs for getting Seal Key

For sealing data to the enclave for caching, OE SDK exposes two methods for an application to take advantage of sealing keys provided by underlying platform:

- Call `oe_get_seal_key_by_policy` to obtain a symmetric key based on the current enclave properties (such as its SecurityVersion and debug state) and your choice of identity properties as specified by the seal policy.

- Call `oe_get_seal_key` to obtain a seal key with the same properties as returned in the keyInfo from a previous call to 
`oe_get_seal_key_by_policy`. This method is used to get the sealing key to unseal previously sealed data.
This is recommended because events such as patching of the server can change the properties used to derive the sealing key
(e.g. CPUSVN) in `oe_get_seal_key_by_policy`. As a best practice, you should persist the `keyInfo` along with your encrypted data for such scenarios.

Once an enclave gets a seal key, it can use it to seal/unseal data.

## Host application

This sample emphasizes on demonstrating how an OE host application initiates seal and unseal operations with simple input data with different policies on enclave environments.

Note: While it's not shown in this sample, seal/unseal operations could be triggered from inside an enclave on the data invisible to host.

### Create three enclaves

- `enclave_a_v1` and `enclave_a_v2` were created and signed by the same private.pem file, which means they share the same signer.

  Notice that in `enc2/Makefile`, instead of generating enc2's own private.pem, it copies the one from enc1, this is how enclave1 and enclave2 shares the same signer.

- `enclave_b` was signed by a newly created private.pem and has a different signer/product identity.

### Seal and unseal data with OE_SEAL_POLICY_UNIQUE in different enclaves

- The host seals a test data string into enclave_a_v1 with `OE_SEAL_POLICY_UNIQUE`, which was done through an `unseal_data()` ecall into enclave1. Upon finishing sealing, a `sealed_data_t` structure is returned back to the host.

- The host unseals the `sealed_data_t` in `enclave_a_v1` and expects to see it's unsealed **successfully** because this sealed data was sealed in the same `enclave_a_v1 enclave`.

- The host unseals the `sealed_data_t` in `enclave_a_v2` and expects to see it **fail** to unseal because this sealed data was not sealed by the same enclave.

- The host unseals the `sealed_data_t` in `enclave_b` and expects to see it **fail** to unseal because this sealed data was not sealed by the same enclave.

### Seal and unseal data with OE_SEAL_POLICY_PRODUCT in different enclaves

- The host seals a test data string into `enclave_a_v1` with `OE_SEAL_POLICY_PRODUCT`, which was done through an `unseal_data()` ecall into enclave1. Upon finishing sealing, a `sealed_data_t` structure is returned back to the host.

- The host unseals the `sealed_data_t` in `enclave_a_v1` and expects to see it's unsealed **successfully** because this sealed data was sealed in the same `enclave_a_v1 enclave`.

- The host unseals the `sealed_data_t` in `enclave_a_v2` and expects to see it **successfully** unseal because this sealed data was signed by the same signature for the same product.

- The host unseals the `sealed_data_t` in `enclave_b` and expects to see it **fail** to unseal because this sealed data was not sealed by the same enclave.

## Enclave library

All three enclaves are almost identical except signed by two different private.pem files.

### ECALLs

There are two ECALLs implemented inside each enclave library.

#### seal_data

```c
int seal_data(int sealPolicy, 
              unsigned char* opt_mgs, size_t opt_msg_len, 
              unsigned char* data, size_t data_size, 
              sealed_data_t** sealed_data, size_t* sealed_data_size)
```

 The enclave allocates the following sealed data structure and fills with iv,encrypted data, and other fields before adding the generated signature to it.
 
```c
typedef struct _sealed_data_t
{
    size_t total_size;
    unsigned char signature[SIGNATURE_LEN];
    unsigned char opt_msg[MAX_OPT_MESSAGE_LEN];
    unsigned char iv[IV_SIZE];
    size_t key_info_size;
    size_t encrypted_data_len; 
    unsigned char encrypted_data[];
} sealed_data_t;
```

- `seal_data` calls `oe_get_seal_key_by_policy` with either `OE_SEAL_POLICY_UNIQUE` or
  `OE_SEAL_POLICY_PRODUCT` to get a unique seal key and its seal key info.
- Generate an initialization vector.
- Encrypt the input data.
- Allocate the `sealed_data_t` structure
- Generate a signature from the `sealed_data_t` structure with the seal key.
- Fill the `sealed_data_t` with above information before returning to the host.

#### unseal_data

```c
int unseal_data(sealed_data_t* sealed_data, size_t sealed_data_size,
                unsigned char** data, size_t* data_size)
```

- `seal_data` calls `oe_get_seal_key` with key info from `sealed_data_t`.
- Retrieve initialization vector from `sealed_data_t.iv`.
- Regenerate a new signature from `sealed_data_t` and validate it against `sealed_data_t.signature`.
- Decrypt `sealed_data_t.encrypted_data`.
- Return the decrypted data before returning to the host.

### Notes

- Security implications with sealing/unsealing: a host is a untrusted entity. And it can load and invoke an enclave in any order they chose. It's important that an enclave implementation does NOT allow the sealing and unsealing capability to leak secrets, or grant unauthorized access to them.

- In a cloud environment, you must not expect that any information sealed by an enclave can be unsealed by it at a future point. This is because the sealing keys generated by platform are machine specific, and your VM may be migrated off a node at any time. For example, if a server is misbehaving and the service healing moves the VM to a different server to maintain a minimum level of service. As such, these APIs should only be used for caching enclave information across restarts of the application or reboots of the VM. It should always be able to fall back to obtaining the sealed data in some other way, such as requesting the secret again from a trusted source via remote attestation.

## Build and run

To build a sample, change directory to your target sample directory and run `make build` to build the sample and run `make run` to run it.

For example:

```bash
yourusername@yourVMname:~/openenclave/share/openenclave/samples$ cd data-sealing
yourusername@yourVMname:~/openenclave/share/openenclave/samples/data-sealing$ make build
yourusername@yourVMname:~/openenclave/share/openenclave/samples/data-sealing$ make run
```
