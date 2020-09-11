# The File-Encryptor Sample

OE SDK comes with a default crypto support library that supports a [subset of the open sources mbedTLS](https://github.com/openenclave/openenclave/blob/master/docs/MbedtlsSupport.md) library.
This sample demonstrates how to perform simple file cryptographic operations inside an enclave using mbedTLS library.

It has the following properties:

- Written in C++
- Show how to encrypt and decrypt data inside an enclave
- Show how to derive a key from a password string using [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)
- Use AES mbedTLS API to perform encryption and decryption
- Use the following OE APIs
  - mbedtls_aes_setkey_*
  - mbedtls_aes_crypt_cbc
  - mbedtls_pkcs5_pbkdf2_hmac
  - mbedtls_ctr_drbg_random
  - mbedtls_entropy_*
  - mbedtls_ctr_drbg_*
  - mbedtls_sha256_*
- Also runs in OE simulation mode

## Host application

This sample is relatively straightforward, It's all about the use of the mbedTLS library.

![Sample components diagram](diagram.png)

The host application drives an enclave to perform the following operations:

1. Create an enclave from the host.

2. Encrypt a `testfile` into `out.encrypted`. It breaks an input file into 16-byte blocks.
   It then sends each block to the enclave for encryption one block after the other until the
   very last block is encountered. It makes sure the last block is padded to make it a 16-byte block,
   which was required AES-CBC encryption algorithm used by the enclave.

3. Decrypt the `out.encrypted` file to the `out.decrypted` file.

   The decryption process is a reverse of the encryption except that it provides a encryption header
   to the encryptor in the enclave in its `initialize_encryptor` call, which contains a
   `encryption_header_t` (defined below), that has encryption metadata for the encryptor
   to validate its password and retrieve the encryption key from it.

   In the end, the host makes sure the contents of `testfile` and `out.decrypted` are identical
   i.e. that the encryption and the decryption produce the expected result.

4. Terminate the enclave.

## Enclave library

### ECALLs

There are three ECALLs implemented inside the enclave library:

### 1. initialize_encryptor

```c
int initialize_encryptor(
    bool encrypt,
    const char* password,
    size_t password_len,
    encryption_header_t* header)
```

The bulk of the operations done in this enclave call involve allocating resources and setting up mbedTLS for encryption and decryption operations.

#### For encryption operation

It does the following operations to generate `encryption_header_t` information for passing back the host to write into the encrypted file.

```c
typedef struct _encryption_header
{
    size_t fileDataSize;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES];
    unsigned char encrypted_key[ENCRYPTION_KEY_SIZE_IN_BYTES];
} encryption_header_t;
```

- Generate a SHA256 digest for the input password, stored in digest field.
- Derive a password key from the input password.
- Produce an encryption key.
- Encrypt the encryption key with the password key, stored in `encrypted_key` field.

See the following routine for implementation details:

```c
int ecall_dispatcher::prepare_encryption_header(
    encryption_header_t* header,
    string password)
```

#### For decryption operation 

In decryption, instead of generating `encryption_header_t` information, initialize_encryptor uses the host provided `encryption_header_t`
information to validate the input password and extract encryption key for later decryption operations.

Here what it does:

- Check password by comparing `encryption_header_t.digest` with the calculated hash of the input password.
- Derive a password key from the input password.
- Decrypt `encryption_header_t.encrypted_key` with the password key produced above, in preparing for upcoming decryption operations.

See the following routine for details:

```c
int ecall_dispatcher::parse_encryption_header(
    encryption_header_t* header,
    string password)
```

#### 2. encrypt_block

```c
int encrypt_block(
    bool encrypt,
    unsigned char* input_buf,
    unsigned char* output_buf,
    size_t size)
```

Send a block of data to the enclave for encryption using the configuration setup up by the `initialize_encryptor()` call.

#### 3. close_encryptor()

```c
void close_encryptor()
```

Free all the resources allocated for this encryptor instance.

## Build and run

To build and run this sample, please refer to documentation provided in the main [README file](../README.md#building-the-samples)

#### Note

The file-encryptor sample can run under OE simulation mode.