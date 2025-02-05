## Prerequisites
 The audience is assumed to be familiar:
 [What is an Attested TLS channel](AttestedTLSREADME.md#what-is-an-attested-tls-channel)

# The Attested TLS sample

It has the following properties:

- Demonstrates attested TLS feature
  - between two enclaves
  - between an enclave application and a non enclave application
- Use of OpenSSL crypto libraries within enclaves for TLS
- If the `OE_CRYPTO_LIB` not set, OpenSSL 3 will be used by default (see [Makefile](Makefile#L8) and [CMakeLists.txt](CMakeLists.txt#L10)).
- To use FIPS-enabled OpenSSL based on SymCrypt engine, set the `OE_CRYPTO_LIB` to `openssl_symcrypt_fips`
- To use FIPS-enabled OpenSSL 3 based on SymCrypt provider, set the `OE_CRYPTO_LIB` to `openssl_3_symcrypt_prov_fips`
- Configure both the server and the client with recommended cipher suites and elliptic curves (refer to the [section](#recommended-tls-configurations-when-using-openssl) for more details).
- Use of following Enclave APIs
  - oe_get_attestation_certificate_with_evidence
  - oe_free_attestation_certificate
  - oe_verify_attestation_certificate_with_evidence

**Note: Currently this sample only works on SGX-FLC systems.** The underlying SGX library support for end-to-end remote attestation is required but available only on SGX-FLC system. There is no plan to back port those libraries to either SGX1 system or software emulator.

## Overall Sample Configuration

In first part of this sample, there are two enclave applications in this sample: one for hosting an TLS client inside an enclave and the other one for an TLS server.

 ![Attested TLS channel between two enclaves](tls_between_enclaves.png)

In the 2nd part of this sample, there is one regular application functioning as a non-enclave TLS client and an enclave application
instantiating an enclave which hosts an TLS server.

 ![Attested TLS channel between a non enclave application and an enclave](tls_between_non_enclave_enclave.png)

Note: Both of them can run on the same machine or separate machines.

### Server application
  - Host part (tls_server_host)
    - Instantiate an enclave before transitioning the control into the enclave via an ecall.
  - Enclave (tls_server_enclave.signed)
    - Call oe_get_attestation_certificate_with_evidence to generate an certificate
    - Use the OpenSSL API to configure a TLS server using the generated certificate
    - Launch a TLS server and wait for client connection request
    - Read client payload and reply with server payload
  - How to launch a server instance
```
../server/host/tls_server_host ../server/enc/tls_server_enc.signed -port:12341
```
### Enclave Client application
  - Host part (tls_client_host)
    - Instantiate an enclave before transitioning the control into the enclave via an ecall.
  - Enclave (tls_client_enclave.signed)
    - Call oe_get_attestation_certificate_with_evidence to generate an certificate
    - Use OpenSSL API to configure an TLS client after configuring above certificate as the client's certificate
    - Launch a TLS client and connect to the server
    - Send client payload and wait for server's payload
  - How to launch a client instance
```
../client/host/tls_client_host ../client/enc/tls_client_enclave.signed -server:localhost -port:12341
```

### Non-enclave Client application
 - When used in this scenario, this non-enclave client is assumed to be a trusted party holding secrets and only shares it with the server after the server is validated
 - Connect to server port via socket
 - Use OpenSSL API to configure a TLS client
 - Call oe_verify_attestation_certificate_with_evidence to validate server's certificate
 - Send client payload and wait for server's payload

```
../client/tls_non_enc_client -server:localhost -port:12341
```

## Build and run

### Linux

#### CMake
- Use OpenSSL
  ```bash
  mkdir build
  cd build
  cmake -DOE_CRYPTO_LIB=openssl ..
  make
  make run
  ```

- Use FIPS-enabled OpenSSL based on SymCrypt engine
  ```bash
  mkdir build
  cd build
  cmake -DOE_CRYPTO_LIB=openssl_symcrypt_fips ..
  make
  make run
  ```

- Use OpenSSL 3.1
  ```bash
  mkdir build
  cd build
  cmake -DOE_CRYPTO_LIB=openssl_3 ..
  make
  make run
  ```

- Use FIPS-enabled OpenSSL 3 based on SymCrypt provider
  ```bash
  mkdir build
  cd build
  cmake -DOE_CRYPTO_LIB=openssl_3_symcrypt_prov_fips ..
  make
  make run
  ```

#### GNU Make
- Use OpenSSL
  ```bash
  make OE_CRYPTO_LIB=openssl build
  make run
  ```

- Use FIPS-enabled OpenSSL based on SymCrypt engine
  ```bash
  make OE_CRYPTO_LIB=openssl_symcrypt_fips build
  make run
  ```

- Use OpenSSL 3.1
  ```bash
  make OE_CRYPTO_LIB=openssl_3 build
  make run
  ```

- Use FIPS-enabled OpenSSL 3 based on SymCrypt provider
  ```bash
  make OE_CRYPTO_LIB=openssl_3_symcrypt_prov_fips build
  make run
  ```

### Windows

#### CMake
- Use OpenSSL
  ```bash
  mkdir build
  cd build
  cmake -G Ninja -DOE_CRYPTO_LIB=openssl ..
  ninja
  ninja run
  ```

- Use FIPS-enabled OpenSSL based on SymCrypt engine
  ```bash
  mkdir build
  cd build
  cmake -G Ninja -DOE_CRYPTO_LIB=openssl_symcrypt_fips ..
  ninja
  ninja run
  ```

- Use OpenSSL 3.1
  ```bash
  mkdir build
  cd build
  cmake -G Ninja -DOE_CRYPTO_LIB=openssl_3 ..
  ninja
  ninja run
  ```

- Use FIPS-enabled OpenSSL 3 based on SymCrypt provider
  ```bash
  mkdir build
  cd build
  cmake -G Ninja -DOE_CRYPTO_LIB=openssl_3_symcrypt_prov_fips ..
  ninja
  ninja run
  ```

Note: This sample has a dependency on the [socket support](../../docs/UsingTheIOSubsystem.md#a-socket-example) added in the OE SDK v0.6.0 release, so it needs to be linked against the liboehostsock and libhostresolver libraries. For more details, see [Using the Open Enclave I/O subsystem](../../docs/UsingTheIOSubsystem.md#opting-in).

### Running attested TLS server in loop
By default the server exits after completing a TLS session with a client. `-server-in-loop` run-time option changes this behavior to allow the TLS server to handle multiple client requests.

On Linux:

```bash
./server/host/tls_server_host ./server/enc/tls_server_enc.signed -port:12341 -server-in-loop
or
make run-server-in-loop
```

On Windows after building the sample as described in the [README file](../README.md#building-the-samples.md):

```cmd
.\server\host\tls_server_host .\server\enc\tls_server_enc.signed -port:12341 -server-in-loop
```
### Recommended TLS configurations when using OpenSSL

  It is strongly recommended that developers configure OpenSSL to restrict the TLS versions, cipher suites and elliptic curves to be used for TLS connections to enclave:

  - TLS protocol versions
    - TLS 1.2
    - TLS 1.3
  - TLS 1.3 cipher suites (in the exact order)
    - TLS13-AES-256-GCM-SHA384
    - TLS13-AES-128-GCM-SHA256
  - TLS 1.2 cipher suites (in the exact order)
    - ECDHE-ECDSA-AES128-GCM-SHA256
    - ECDHE-ECDSA-AES256-GCM-SHA384
    - ECDHE-RSA-"AES128-GCM-SHA256
    - ECDHE-RSA-AES256-GCM-SHA384
    - ECDHE-ECDSA-AES128-SHA256
    - ECDHE-ECDSA-AES256-SHA384
    - ECDHE-RSA-AES128-SHA256
    - ECDHE-RSA-AES256-SHA384
  - Elliptic curves
    - P-521
    - P-384
    - P-256

  This sample illustrates how to use [`initalize_ssl_context()`](common/openssl_utility.cpp#L118) to configure the `SSL_CTX` as suggested in both the [server](server/enc/openssl_server.cpp#L147) and the [client](client/enc/openssl_client.cpp#L200) modules.