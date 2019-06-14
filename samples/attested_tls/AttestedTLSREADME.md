# Secure Channel in OE SDK

  As Open Enclave SDK getting adopted into more realistic scenarios, we are receiving requests from OE SDK developers for adding secure channel support.

  We do have the remote_attestation sample that shows how to conduct remote attestation between two enclaves and establish a `proprietary` channel based on asymmetric keys exchanged during the attestation process. It demonstrates how to conduct mutual attestation but it does not go all the way to show how to establish a fully secure channel.

  Most of the real world software uses TLS-like standard protocol through popular TLS APIs (OpenSSL, WolfSSL, Mbedtls...) for establishing secure channels. Thus, instead of inventing a new communication protocol, we implemented `Attested TLS` feature to address above customer need by adding a set of new OE SDK APIs to help seamlessly integrate remote attestation into the popular TLS protocol for establishing an TLS channel with attested connecting party without modifying existing TLS APIs (such as OpenSSL, Mbedtls, and others).

# What is an Attested TLS channel

The remote attestation feature that comes with TEE (such as Intel SGX or ARM's TrustZone enclave, in the context of this doc) could significantly improve a TLS endpoint (client or server) trustworthiness for a TLS connection starting or terminating inside an enclave. An Attested TLS channel is a TLS channel that integrates remote attestation validation as part of the TLS channel establishing process. Once established, it guarantees that an attested connecting party is running inside a TEE with expected identity.

There are two types of Attested TLS connections:
1. Both ends of an Attested TLS channel terminate inside TEE
    - Guarantee that both parties of a TLS channel are running inside trustes TEEs
    - OE SDK sample: tls_between_enclave
2. Only one end of an Attested TLS channel terminate inside TEE
    - In this case, the assumption is that the end not terminated inside an TEE is a trust party. The most common use case is, this non-Tee party might have secrets to securely share with the other party through an Attested TLS channel.
    - OE SDK sample: tls_between_host_enclave

## Prerequisites

  The audience is assumed to be familiar:

  - [Transport Layer Security (TLS)](https://en.wikipedia.org/wiki/Transport_Layer_Security) a cryptographic protocol designed to provide communications security over a computer network.

  - [Open Enclave Remote Attestation](https://github.com/Microsoft/openenclave/tree/master/samples/remote_attestation#what-is-attestation): Remote Attestation is the concept of a HW entity or of a
combination of HW and SW gaining the trust of a remote provider or producer.

### How it works

  By taking advantage of the fact that TLS involving parties use public-key cryptography for identity authentication during the [TLS handshaking process](https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake), the Attested TLS feature uses a self-signed X509.V3 certificate to represent a TLS endpoint's identity. We make this certificate cryptographically bound to this specific enclave instance by adding a custom certificate extension (called quote extension) with this enclave's attestation quote that has the certificate's public key information embedded.

  A new API oe_generate_attestation_certificate was added for generation such a self-signed certificate for use in the TLS handshaking process

#### Generate TLS certificate

  A connecting party needs to provide a key pair for the oe_generate_attestation_certificate api to produce a self-signed certificate. These keys could be transient keys and unique for each new TLS connection.
  - a private key (pkey): used for generating a certificate and represent the identity of the TLS connecting party
  - a public key (pubkey): used in the TLS handshake process to create a digital signature in every TLS connection,

```
/**
 * oe_generate_attestation_certificate.
 *
 * This function generates a self-signed x.509 certificate with an embedded
 * quote from the underlying enclave.
 *
 * @param[in] subject_name a string contains an X.509 distinguished
 * name (DN) for customizing the generated certificate. This name is also used
 * as the issuer name because this is a self-signed certificate
 * See RFC5280 (https://tools.ietf.org/html/rfc5280) specification for details
 * Example value "CN=Open Enclave SDK,O=OESDK TLS,C=US"
 *
 * @param[in] private_key a private key used to sign this certificate
 * @param[in] private_key_size The size of the private_key buffer
 * @param[in] public_key a public key used as the certificate's subject key
 * @param[in] public_key_size The size of the public_key buffer.
 *
 * @param[out] output_cert a pointer to buffer pointer
 * @param[out] output_cert_size size of the buffer above
 *
 * @return OE_OK on success
 */
oe_result_t oe_generate_attestation_certificate(
    const unsigned char* subject_name,
    uint8_t* private_key,
    size_t private_key_size,
    uint8_t* public_key,
    size_t public_key_size,
    uint8_t** output_cert,
    size_t* output_cert_size);
```
#### Authenticate peer certificate

Upon receiving a certificate from the peer endpoint, a connecting party needs to perform peer certificate validation.

In this feature, instead of using the TLS API's default authentication routine, which validates the certificate against a pre-determined CAs for authentication, an application needs to conduct "Extended custom certificate validation" inside the peer custom certificate verification callback (cert_verify_callback), which is supported by all the popular TLS APIs.

```
For example:

    Mbedtls:
            void mbedtls_ssl_conf_verify(
                      mbedtls_ssl_config *conf,
                      int(*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *)
                      void *p_vrfy)

    OpenSSL:
            void SSL_CTX_set_verify(
                      SSL_CTX *ctx, int mode,
                      int (*verify_callback)(int, X509_STORE_CTX *))
```
##### Custom extended certificate validation

The following four validation steps are performed inside the cert_verify_callback
  1. Validate certificate
     - Verify the signature on the self-signed certificate to ascertain that the attestation report is genuine and unmodified.
  2. Validate the quote
     - Extract this quote extension from the certificate
     - Perform quote validation
  3. Validate the connection between the certificate and  the quote:
     - Compute the SHA256 hash of the certificate's public key and compare this against the report’s user data in the quote
     - If they match, it proves the certificate was cryptographically tied to the quote because hash of the public key was used as report data during quote generation
  4. Validate peer enclave's identity
     - Validate the enclave’s identity (e.g., MRENCLAVE in SGX) against the expected list. This check ensures only the intended party is allowed to connect to.

  A new OE API, oe_verify_attestation_certificate(), was added to perform step 1-3 and leaving step 4 to application for business logic, which can be done inside a caller-registered callback, enclave_identity_callback, a callback parameter to oe_verify_attestation_certificate() call.

  A caller wants to fail cert_verify_callback with non-zero code if either certificate signature validation failed or unexpected TEE identity was found. This failure return will cause the TLS handshaking process to terminate immediately, thus preventing establishing connection with a unqualified connecting party.

```
/**
 * identity validation callback type
 * @param[in] identity a pointer to an enclave's identity information
 * @param[in] arg caller defined context
 */
typedef oe_result_t (
    *oe_identity_verify_callback_t)(oe_identity_t* identity, void* arg);

/**
 * oe_verify_attestation_certificate
 *
 * This function perform a custom validation on the input certificate. This
 * validation includes extracting an attestation evidence extension from the
 * certificate before validating this evidence. An optional
 * enclave_identity_callback could be passed in for a calling client to further
 * validate the identity of the enclave creating the quote.
 * @param[in] cert_in_der a pointer to buffer holding certificate contents
 *  in DER format
 * @param[in] cert_in_der_len size of certificate buffer above
 * @param[in] enclave_identity_callback callback routine for custom identity
 * checking
 * @param[in] arg an optional context pointer argument specified by the caller
 * when setting callback
 * @retval OE_OK on a successful validation
 * @retval OE_VERIFY_FAILED on quote failure
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid
 * @retval OE_FAILURE general failure
 * @retval other appropriate error code
 */

oe_result_t oe_verify_attestation_certificate(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_identity_verify_callback_t enclave_identity_callback,
    void* arg);
```
   Once the received certificate passed above validation, the TLS handshaking process can continue until an connection is established. Once connected, a connecting party can be confident that the other connecting party is indeed a specific enclave image running inside a TEE.

In the case of establishing a Attested TLS channel between two enclaves, the same authentication process could be applied to both directions in the TLS handshaking process to establish an mutually attested TLS channel between two enclaves.

 Please see OE SDK samples for how to use those new APIs along with your favorite TLS library.
