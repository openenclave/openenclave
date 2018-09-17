# The File-Encryptor Sample

 OE SDK comes with a default crypto support library that supports a [subset of the open sources mbedtls](/docs/MbedtlsSupport.md) library. This sample demonstrates how to perform simple file crypotology operations inside an enclave using mbedtls library.
   
It has the following properties:

- Written in C++
- Shows how to encrypt and decrypt data inside an enclave
- Shows how to derive a key from a password string [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)
- Use AES mbedtls API to perform encryption and descryption
- OE APIs used
  - mbedtls_aes_setkey_*
  - mbedtls_aes_crypt_cbc
  - mbedtls_pkcs5_pbkdf2_hmac
  - mbedtls_ctr_drbg_random
  - mbedtls_entropy_*
  - mbedtls_ctr_drbg_*
  - mbedtls_sha256_*
  - oe_is_outside_enclave
  
## Host application

This sample is relatively straightforward, It's all about the use of the mbedtls library. 

![Sample components diagram](diagram.png)

The host application drives an enclave to perform the following operations

1. Creates an enclave from the host

2. Encrypts a testfile into out.encrypted file. It breaks an input file into 16-byte blocks. It then sends each block to the enclave for encryption one block after the other until the very last block is encountered. It makes sure the last block is padded to make it a 16-byte block, which was required AES-CBC encryption algorithm used by the enclave.

3. Decrypts the out.encrypted to out.decrypted file

    The decryption process is a reverse of the encryption except that it provides a encryption header to the encryptor in the enclave in its InitializeEncryptor call, which contains a **EncryptionHeader** (defined below), that has encryption metadata for the encryptor to validate its password and retrieve the encryption key from it.

   In the end, the host makes sure the contents of testfile and out.decrypted are identical; that is, the encryption and the decryption actual work as expected.

4. Terminate the enclave

## Enclave library

### ECALLs

  There are three ECALLs implemented inside the enclave library

### OE_ECALL void InitializeEncryptor(EncryptInitializeArgs* args)

  The bulk of the operations are done in this enclave call.

   Allocate resource and setup mbedtls for encryption and decryption operations. 
   
#### For encryption operation

   It does the following operations to generate EncryptionHeader information for passing back the host to write into the encrypted file.

  ```c
  typedef struct _EncryptionHeader
  {
      size_t fileDataSize;
      unsigned char digest[HASH_VALUE_SIZE_IN_BYTES];
      unsigned char encryptedKey[ENCRYPTION_KEY_SIZE_IN_BYTES];
  } EncryptionHeader;
  ```

  - Generate a SHA256 digest for the input password, stored in digest field
  - Derive a password key from the input password
  - Produce an encryption key
  - Encrypt the encryption key with the password key, stored in encryptedKey field

See the following routine for details

```c
int ECallDispatcher::prepareEncryptionHeader(
    EncryptionHeader* pHeader,
    string password)
```
    
#### For decryption operation 

 In decryption, instead of generating EncryptionHeader information, InitializeEncryptor uses the host provided EncryptionHeader information to validate the input password and extract encryption key for later decryption operations.
 
 Here what it does:
 
 - Check password by comparing EncryptionHeader.digest with the calculated hash of the input password
 - Derive a password key from the input password
 - Decrypt EncryptionHeader.encryptedKey with the password key produced above, in preparing for upcoming decryption operations
 
 
 
See the following routine for details

```c
    int ECallDispatcher::parseEncryptionHeader(
        EncryptionHeader* pHeader,
        string password)
```

#### OE_ECALL void EncryptBlock(EncryptBlockArgs* args)

Send a block of data to the enclave for encryption using the configuration setup up by the InitializeEncryptor() call

#### OE_ECALL void CloseEncryptor(CloseEncryptorArgs* args)
  
   Free all the source allocated as part of this encryptor instance.
 
## A few things demonstrated in this enclave

1. An ECallDispatcher class object was defined to make it easier to organize ECALLs implementation in the context of C++. All the ECALLs are dispatched from the ECallDispatcher **dispatcher** object. A macro DISPATCH(x) was defined to do the actual ECALLs dispatching work into **dispatcher** object's each corresponding method.

2. For security reasons, all the ECALLs are strongly recommended to check whether input and output buffers are in host’s address space to avoid enclave data leaked to the untrusted host

    Here is why:

    A host application cannot be trusted. And since a host knows the layout and address range of the enclave, the host could pass in an argument structure whose address is within the enclave itself. Then the enclave could overwrite its own memory. This is similar to a buffer-overrun attack. Or the host could trick an enclave to reveal its memory contents. To prevent this kind of security concerns, an enclave must check that args memory that passed to it form the host really resides within the host address space.

    This following OE API could be used for this kind of memory range checking

    ```c
    oe_is_outside_enclave(args, sizeof(args)))
    ```

    In this sample, above checking was added into DISPATCH(x) macro, which benefits all the ECALLs without duplicating code in each ECALL. 

    The same memory range checking should be applied to all nested buffers inside the args structure.
 
3. Copy the input/output buffer locally, into enclave's address range, inside the enclave before processing it.

    A host might update the args (such as the size of a buffer) parameters between enclave’s reading of the args, which is very difficult to detect. This belongs to the *Time of check to time of use[(TOCTTOU)](https://en.wikipedia.org/wiki/Time_of_check_to_time_of_use)* class of software bugs.

    In this example, before operating on it, the *password* information originated from the InitializeEncryptor ECall was copied from args->password, which resides in the host memory range, over to enclave memory for avoiding TOCTTOU type attack.


## Build and run

To build a sample, change directory to your target sample directory and run "make build" to build the sample and run "make run" to run it.

For example:

     yourusername@yourVMname:~/openenclave/share/openenclave/samples$ cd file-encryptor
     yourusername@yourVMname:~/openenclave/share/openenclave/samples/file-encryptor$ make build
     yourusername@yourVMname:~/openenclave/share/openenclave/samples/file-encryptor$ make run
