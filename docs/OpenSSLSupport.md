# Open Enclave Support for OpenSSL

The OpenSSL on OE is configured with following options
- no-afalgeng
  - Disable the AF_ALG hardware engine.
- no-autoerrinit
- no-autoload-config
- no-aria
  - Disable ARIA block cipher.
- no-blake2
  - Disable Blake2.
- no-bf
  - Disable Blowfish.
- no-camellia
  - Disable camellia.
- no-cast
  - Disable CAST5 block cipher.
- no-capieng
  - Disable the Microsoft CryptoAPI engine.
- no-cms
  - Disable cryptographic message syntax that handles S/MIME v3.1 mail.
- no-ct
  - Disable certificate transparency as it depends on host file system (CT log files).
- no-dso
  - Disable the OpenSSL DSO API.
- no-gost
  - Disable the Russian GOST crypto engine that requires dynamic loading.
- no-hw
- no-idea
  - Disable IDEA.
- no-md2
  - Disable MD2.
- no-md4
  - Disable MD4.
- no-mdc2
  - Disable MDC2.
- no-nextprotoneg
  - Disable Next Protocol Negotiation (NPN).
- no-psk
  - Disable PSK.
- no-poly1305
  - Disable Poly-1305.
- no-rfc3779
  - Disable RFC 3379 (Delegated Path Discovery).
- no-rmd160
  - Disable RIPEMD-160.
- no-seed
  - Disable SEED ciphersuites.
- no-rc4
  - Disable RC4.
- no-shared
- no-sm2
  - Disable Chinese cryptographic algorithms.
- no-sm3
  - Disable Chinese cryptographic algorithms.
- no-sm4
  - Disable Chinese cryptographic algorithms
- no-siphash
  - Disable SipHash.
- no-scrypt
  - Disable scrypt KDF.
- no-srp
  - Disable Secure Remote Password (SRP).
- no-ssl2
- no-ssl3
- no-whirlpool
  - Disable Whirlpool hash.
- no-threads
- no-ui-console
  - Disable support for the openssl command-line tool that is not required by OE.
- no-zlib
  - Disable the ZLIb support.
- --with-rand-seed=none

*Note:* The autoalginit option is required by APIs (e.g., EVP) that retrieve algorithms by name so
can not be disabled.

OE also explicitly disables the following feature:
- SECURE_MEMORY
  - Require mman features (e.g., madvise, mlock, mprotect) that are not supported inside an enclave.

In addition, OpenSSL by default disables the following algorithms/features
- MD2
- RC5
- EC_NISTP_64_GCC_128
- EGD (Entropy Gathering Daemon)
- Heartbeats extension
- SCTP (Stream Control Transimission Protocol) protocol

*NOTE*: The current support is still experimental and for SGX only. To use OpenSSL libraries, developers should specify
`-DBUILD_OPENSSL=ON` cmake option when building the OE SDK.

# How to use RAND APIs

Currently, the default RAND method used by RAND APIs is not supported by OE. More specifically,
the default OpenSSL RAND method relies on the `rdtsc` instruction, which is not supported by SGXv1 enclaves.
Therefore, OE currently does not support RAND APIs if users try to use them directly (by default, the RAND APIs depend on the default
RAND method). To enable RAND APIs, OE recommends to use the OpenSSL RDRAND engine, which explicitly replaces the
default RAND method with the `rdrand`-based method. That is, the RAND APIs will obtain the random bytes directly using the
`rdrand` instruction. To opt-in the RDRAND engine, see the following example.

```c
void enc_rand()
{
    int data = 0;
    ENGINE* eng = NULL;

    /* Initialize and opt-in the RDRAND engine. */
    ENGINE_load_rdrand();
    eng = ENGINE_by_id("rdrand");
    if (eng == NULL)
    {
        goto done;
    }

    if (!ENGINE_init(eng))
    {
        goto done;
    }

    if (!ENGINE_set_default(eng, ENGINE_METHOD_RAND))
    {
        goto done;
    }

    /* Now RAND APIs are available. */

    /* Test the RAND_bytes API. */
    if (!RAND_bytes((unsigned char*)&data, sizeof(data)))
    {
        goto done;
    }

    printf("RAND_bytes() %d\n", data);

done:

    /* cleanup to avoid memory leak. */
    ENGINE_finish(eng);
    ENGINE_free(eng);
    ENGINE_cleanup();

    return;
}
```

Note that the code snippet for the RDRAND engine opt-in is required to use not only RAND APIs
but also other OpenSSL APIs that internally depend on the RAND APIs. Alternatively, developers
can implement their own RAND method to replace the default method via `RAND_set_rand_method` API.

## Security Guidance for using OpenSSL APIs/Macros

OpenSSL provides APIs that allow users to configure sensitive settings like certificate trust and cipher suite preference from files.
Because the host file system is considered untrusted in contexts such as SGX enclaves, OE SDK marks these APIs as unsupported to discourage their use.
OE SDK does this by patching the OpenSSL headers that include such APIs or macros (i.e., appending the inclusion of an "unsupported.h" file to these headers).
This ensures that when an enclave includes a patched OpenSSL header and uses the specific API or macro, user will receive compile-time errors.
The errors can be disabled by specifying the `OE_OPENSSL_SUPPRESS_UNSUPPORTED` option to the compiler.

See the following table for the detailed list of APIs/Macros.

API / Macro | Original header | Comments | Guidance |
:---:|:---:|:---|:---|
OPENSSL_INIT_LOAD_CONFIG | crypto.h | The macro represents an option to the OPENSSL_init_ssl and OPENSSL_init_crypto APIs that initializes an application based on the openssl.cnf (loaded from the host filesystem). Therefore, the use of this option would allow an untrusted host to fully control the initialization of the application. | The recommendation is not to invoke initialization APIs with this option. Note that starting from v1.1.0, the explicit initialization is not required. |
SSL_CTX_load_verify_locations | ssl.h | The API specifies the default locations from which an application looks up CA certificates for verification purposes. The API would allow an untrusted host to fully control what certificates the application will trust. | The recommendation is using the SSL_CTX_set_cert_store API that specifies an in-memory certificate verification storage (`X509_STORE`). Another alternative is to implement a customized verification callback and sets the callback via the SSL_CTX_set_verify API, which effectively bypasses the default implementation. |
SSL_CTX_set_default_verify_paths | ssl.h | The API specifies the locations as part of arguments from which an application looks up CA certificates for verification purposes. The API would allow an untrusted host to fully control what certificates the application will trust. | The recommendation is using the SSL_CTX_set_cert_store API that specifies an in-memory certificate verification storage (`X509_STORE`). Another alternative is to implement a customized verification callback and sets the callback via the SSL_CTX_set_verify API, which effectively bypasses the default implementation. |
SSL_CTX_set_default_verify_dir | ssl.h | Similar to SSL_CTX_set_default_verify_paths except for specifying dir only. | The recommendation is using the SSL_CTX_set_cert_store API that specifies an in-memory certificate verification storage (`X509_STORE`). Another alternative is to implement a customized verification callback and sets the callback via the SSL_CTX_set_verify API, which effectively bypasses the default implementation. |
SSL_CTX_set_default_verify_file | ssl.h | Similar to SSL_CTX_set_default_verify_paths except for specifying file only. | The recommendation is using the SSL_CTX_set_cert_store API that specifies an in-memory certificate verification storage (`X509_STORE`). Another alternative is to implement a customized verification callback and sets the callback via the SSL_CTX_set_verify API, which effectively bypasses the default implementation. |
X509_LOOKUP_hash_dir | x509_vfy.h | This API returns a `X509_LOOKUP_METHOD` method that loads files (certificates or CRLs) from the path specified by the `SSL_CERT_DIR` environment variable. This would allow an untrusted host to control what files the enclave will load. The API is used internally by SSL_CTX_set_default_verify_dir and SSL_CTX_set_default_verify_paths. | The recommendation is to implement a customized `X509_LOOKUP_METHOD` method based on in-memory operations. Note that to opt-in the new method, the user needs to explicitly register the method to a `X509_STORE` via the X509_STORE_add_lookup API and the set the `X509_STORE` to an `SSL_CTX` via SSL_CTX_set_cert_store. |
X509_LOOKUP_file | x509_vfy.h | This API returns a `X509_LOOKUP_METHOD` method that loads files (certificates or CRLs) from the path specified by the `SSL_CERT_FILE` environment variable. This would allow an untrusted host to control what files the enclave will load. The API is used internally by SSL_CTX_set_default_verify_file and SSL_CTX_set_default_verify_paths. | The recommendation is to implement a customized `X509_LOOKUP_METHOD` method based on in-memory operations. Note that to opt-in the new method, the user needs to explicitly register the method to a `X509_STORE` via the X509_STORE_add_lookup API and the set the `X509_STORE` to an `SSL_CTX` via SSL_CTX_set_cert_store. |
X509_STORE_load_locations | x509_vfy.h | The API adds X509_LOOKUP_file or X509_LOOKUP_hash_dir to a `X509_STORE` via the X509_STORE_add_lookup API. The API is used internally by SSL_CTX_load_verify_locations. | The recommendation is to add a customized `X509_LOOKUP_METHOD` method to the `X509_STORE` via X509_STORE_add_lookup. |
X509_STORE_set_default_paths | x509_vfy.h | The API adds X509_LOOKUP_file or X509_LOOKUP_hash_dir to a `X509_STORE` via X509_STORE_add_lookup. The API is used internally by SSL_CTX_set_default_verify_paths. | The recommendation is to add a customized `X509_LOOKUP_METHOD` method to the `X509_STORE` via X509_STORE_add_lookup. |
X509_load_cert_file | x509_vfy.h | The API loads certificates from the untrusted host filesystem and adds the certificates to the `X509_STORE` via the X509_STORE_add_cert API. The API is used internally by X509_LOOKUP_hash_dir and X509_LOOKUP_file methods. | The recommendation is not to use this API. An alternative is obtaining in-memory certificates in a secure manner (e.g., secure channel, encrypted storage) and adding the certificates to the `X509_STORE` via X509_STORE_add_cert. |
X509_load_crl_file | x509_vfy.h | The API loads CRL from the untrusted host filesystem and adds the CRL to the `X509_STORE` via the X509_STORE_add_crl API. The API is used internally by X509_LOOKUP_hash_dir and X509_LOOKUP_file methods. | The recommendation is not to use this API. An alternative is obtaining in-memory certificates in a secure manner (e.g., secure channel, encrypted storage) and adding the CRL to the `X509_STORE` via X509_STORE_add_crl. |
X509_load_cert_crl_file | x509_vfy.h | The API is the combination of X509_load_cert_file and X509_load_crl_file. | The recommendation is not to use this API. An alternative is obtaining in-memory certificates in a secure manner (e.g., secure channel, encrypted storage) and adding the certificates/CRL to the `X509_STORE` via X509_STORE_add_cert/X509_STORE_add_crl. |

## API Support

Header | Supported | Comments |
:---:|:---:|:---|
aes.h | Yes | - |
asn1.h | Yes | ASN1_TIME_* APIs tests (asn1_test_time) is disabled. Refer to the [unsuppored test list](/tests/openssl/tests.unsupported) for more detail. |
asn1_mac.h | Yes | - |
asn1err.h | Yes | - |
asn1t.h | Yes | - |
async.h | Yes | - |
asyncerr.h | Yes | - |
bio.h | Partial | SCTP support is disabled by default. |
bioerr.h | Yes | - |
blowfish.h | No | Blowfish is disabled by default. |
bn.h | Yes | - |
bnerr.h | Yes | - |
buffer.h | Yes | - |
buffererr.h | Yes | - |
camellia.h | No | Camellia is disabled by OE. |
cast.h | No | CAST5 is disabled by OE. |
cmac.h | Yes | - |
cms.h | Yes | - |
cmserr.h | Yes | - |
comp.h | Yes | - |
comperr.h | Yes | - |
conf.h | Yes | - |
conf_api.h | Yes | - |
conferr.h | Yes | - |
crypto.h | Yes | SECURE_MEMORY APIs (e.g., CRYPTO_secure_malloc, CRYPT_secure_free) are disabled. The `OPENSSL_INIT_LOAD_CONFIG` macro is disabled for security concerns. Refer to [Security Guidance for using OpenSSL APIs/Macros](#security-guidance-for-using-openssl-apismacros) for more detail. |
cryptoerr.h | Yes | - |
ct.h | No | Certificate Transparency is disabled by OE. |
cterr.h | Yes | - |
des.h | Yes | - |
dh.h | Yes | - |
dherr.h | Yes | - |
dsa.h | Yes | - |
dsaerr.h | Yes | - |
dtls1.h | Yes | - |
e_os2.h | Yes | - |
ebcdic.h | Yes | - |
ec.h | Partial | EC_NISTP_64_GCC_128 is disabled by default. |
ecdh.h | Yes | - |
ecdsa.h | Yes | - |
ecerr.h | Yes | - |
engine.h | Yes | - |
engineerr.h | Yes | - |
err.h | Yes | - |
evp.h | Partial | MD2 and RC5 are disabled by default. |
evperr.h | Yes | - |
hmac.h | Yes | - |
idea.h | No | IDEA is disabled by OE. |
kdf.h | Yes | - |
kdferr.h | Yes | - |
lhash.h | Yes | The lhash test is disabled becuase of requiring too much heap size. Refer to the [unsuppored test list](/tests/openssl/tests.unsupported) for more detail. |
md2.h | No | MD2 is disabled by default (header is present). |
md4.h | No | MD4 is disabled by OE. |
md5.h | Yes | - |
mdc2.h | No | MDC2 is disabled by OE. |
modes.h | Yes | - |
obj_mac.h | Yes | - |
objects.h | Yes | - |
objectserr.h | Yes | - |
ocsp.h | Yes | - |
ocsperr.h | Yes | - |
opensslv.h | Yes | - |
ossl_typ.h | Yes | - |
pem.h | Yes | - |
pem2.h | Yes | - |
pemerr.h | Yes | - |
pkcs12.h | Yes | - |
pkcs12err.h | Yes | - |
pkcs7.h | Yes | - |
pkcs7err.h | Yes | - |
rand.h | Partial | EGD is disabled by default. The default method (RAND_OpenSSL) does not work because the depending `rdtsc` instruction is not supported by SGXv1. Refer to [How to use RAND APIs](#how-to-use-rand-apis) for more detail. |
rand_drbg.h | Partial | OE by default does not depend on the default rand method. Therefore, rand_drbg APIs are supported but have no impact on rand APIs. The drbg test is disabled. Refer to the [unsuppored test list](/tests/openssl/tests.unsupported) for more detail. |
randerr.h | Yes | - |
rc2.h | Yes | - |
rc4.h | No | RC4 is disabled by OE. |
rc5.h | No | RC5 is disabled by default (header is present). |
ripemd.h | No | RIPEMD-160 is disabled by OE.  |
rsa.h | Yes | - |
rsaerr.h | Yes | - |
safestack.h | Yes | - |
seed.h | No | SEED is disabled by OE. |
sha.h | Yes | - |
srp.h | No | SRC is disabled by OE. |
srtp.h | Yes | - |
ssl.h | Partial | SSL2 and SSL3 methods are disabled. Heartbeats extension is disabled by default. Functions that are unsupported by OE for security concerns include: `SSL_CTX_set_default_verify_paths`, `SSL_CTX_set_default_verify_dir`, `SSL_CTX_set_default_verify_file`, `SSL_CTX_load_verify_locations`. Refer to [Security Guidance for using OpenSSL APIs/Macros](#security-guidance-for-using-openssl-apismacros) for more detail |
ssl2.h | Yes | - |
ssl3.h | Yes | - |
sslerr.h | Yes | - |
stack.h | Yes | - |
store.h | Yes | - |
storeerr.h | Yes | - |
symhacks.h | Yes | - |
tls1.h | Partial | Heartbeats extension is disabled by default. |
ts.h | Yes | - |
tserr.h | Yes | - |
txt_db.h | Yes | - |
ui.h | No | Configured with no-ui-console. |
uierr.h | Yes | - |
whrlpool.h | No | Whirlpool is disabled by OE. |
x509.h | Yes | - |
x509_vfy.h | Partial | Functions that are unsupported by OE for security concerns include: `X509_load_cert_file`, `X509_load_crl_file`, `X509_LOOKUP_hash_dir`, `X509_LOOKUP_file`, `X509_load_cert_crl_file`, `X509_STORE_load_locations`, `X509_STORE_set_default_paths`. Refer to [Security Guidance for using OpenSSL APIs/Macros](#security-guidance-for-using-openssl-apismacros) for more detail. |
x509err.h | Yes | - |
x509v3.h | Yes | - |
x509v3err.h | Yes | - |
