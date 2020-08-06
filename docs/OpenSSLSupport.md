# Open Enclave Support for OpenSSL

The OpenSSL on OE is configured with following options
- no-hw
- no-shared
- no-threads
- no-dso
- no-ssl2
- no-ss3
- --with-rand-seed=none

OE also explicitly disables the following features
- AFALGENG (AF_ALG hardware engine)
  - Require special hardware.
- GOST (Russian GOST crypto engine)
  - Require dynamic loading.
- SECURE_MEMORY
  - Require mman features (e.g., madvise, mlock, mprotect) that are not supported inside an enclave.
- UI_CONSOLE
  - Used by the openssl command-line tool that is not required by OE.

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
blowfish.h | Yes | - |
bn.h | Yes | - |
bnerr.h | Yes | - |
buffer.h | Yes | - |
buffererr.h | Yes | - |
camellia.h | Yes | - |
cast.h | Yes | - |
cmac.h | Yes | - |
cms.h | Yes | - |
cmserr.h | Yes | - |
comp.h | Yes | - |
comperr.h | Yes | - |
conf.h | Yes | - |
conf_api.h | Yes | - |
conferr.h | Yes | - |
crypto.h | Yes | SECURE_MEMORY APIs (e.g., CRYPTO_secure_malloc, CRYPT_secure_free) are disabled. |
cryptoerr.h | Yes | - |
ct.h | Yes | - |
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
idea.h | Yes | - |
kdf.h | Yes | - |
kdferr.h | Yes | - |
lhash.h | Yes | The lhash test is disabled becuase of requiring too much heap size. Refer to the [unsuppored test list](/tests/openssl/tests.unsupported) for more detail. |
md2.h | No | MD2 is disabled by default (header is present). |
md4.h | Yes | - |
md5.h | Yes | - |
mdc2.h | Yes | - |
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
rc4.h | Yes | - |
rc5.h | No | RC5 is disabled by default (header is present). |
ripemd.h | Yes | - |
rsa.h | Yes | - |
rsaerr.h | Yes | - |
safestack.h | Yes | - |
seed.h | Yes | - |
sha.h | Yes | - |
srp.h | Yes | - |
srtp.h | Yes | - |
ssl.h | Partial | SSL2 and SSL3 methods are disabled. Heartbeats extension is disabled by defailt. |
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
ui.h | No | Built with OPENSSL_NO_UI_CONSOLE. |
uierr.h | Yes | - |
whrlpool.h | Yes | - |
x509.h | Yes | - |
x509_vfy.h | Yes | - |
x509err.h | Yes | - |
x509v3.h | Yes | - |
x509v3err.h | Yes | - |
