## Prerequisites

 The audience is assumed to be familiar:

 [What is an Attested TLS channel](../tls_between_enclaves/AttestedTLSREADME.md#what-is-an-attested-tls-channel)

# The tls_between_host_enclave sample

It has the following properties:

- Demonstrates attested TLS feature between an enclave application and a non enclave application
- Use of mbedTLS within enclaves for TLS
- Enclave APIs used:
  - oe_generate_attestation_certificate
  - oe_free_attestation_certificate
  - oe_verify_attestation_certificate

**Note: Currently this sample only works on SGX-FLC systems.** The underlying SGX library support for end-to-end remote attestation is required but available only on SGX-FLC system. There is no plan to back port those libraries to either SGX1 system or software emulator.

## Overall Sample Configuraton

 ![Attested TLS channel between a host and an enclave](tls_between_host_enclave.png)

In this sample, there is one regular applcation functioning as a TLS client and an enclave application
instantiating an enclave which hosts an TLS server. Both of them can run on the same machine or separate machines. For convenience, you can run both of on the same machine.

### Server application
  - Host part (tls_server_host)
    - Instantiate an enclave before transitioning the control into the enclave via an ecall.
  - Enclave (tls_server_enclave.signed)
    - Calls oe_generate_attestation_certificate to genreate an certificate
    - Use Mbedtls API to configure an TLS server after configuring above certificate as the server's certificate
    - Launch a TLS server and wait for client connection request
    - Read client payload and reply with server payload
  - How to launch a server instance

```
	./server/host/tls_server_host ./server/enc/tls_server_enc.signed -port:12341 &
```

### Client application
 - Connect to server port via socket
 - Use OpenSSL API to configure a TLS client
 - Call oe_verify_attestation_certificate to validate server's certificate
 - Send client payload and wait for server's payload

```
	./client/tls_client -server:localhost -port:12341
```

## Build and run

Note that there are two different build systems supported, one using GNU Make and
`pkg-config`, the other using CMake.

### CMake

This uses the CMake package provided by the Open Enclave SDK.

```bash
cd tls_between_host_enclave
mkdir build && cd build
cmake ..
make run
```

### GNU Make

```bash
cd tls_between_host_enclave
make build
make run
```
