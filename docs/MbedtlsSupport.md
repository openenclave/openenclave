# Open Enclave Support for mbedtls

Header | Supported | Comments |
:---:|:---:|:---:|
aes.h | Partial | Unsupported functions: mbedtls_aes_crypt_cfb128(), mbedtls_aes_crypt_cfb8() |
aesni.h | No | - |
arc4.h | No | - |
asn1.h | Yes | -|
asn1write.h | Yes | - |
base64.h | Yes | - |
bignum.h | Partial | Unsupported functions: mbedtls_mpi_read_file(), mbedtls_mpi_write_file() |
blowfish.h | No | - |
camellia.h | No | - |
ccm.h | Yes | - |
cipher.h | Yes | - |
cmac.h | Yes | - |
ctr_drbg.h | Partial | Unsupported functions: mbedtls_ctr_drbg_write_seed_file(), mbedtls_ctr_drbg_update_seed_file() |
debug.h | Yes | - |
des.h | Yes | - |
dhm.h | No | - |
ecdh.h | Yes | - |
ecdsa.h | Partial | Unsupported function: mbedtls_ecdsa_sign_det() |
ecjpake.h | No | - |
ecp.h | Yes | - |
ecp_internal.h | No  | - |
entropy.h | Partial | Unsupported functions: mbedtls_entropy_update_nv_seed(), mbedtls_entropy_write_seed_file(), mbedtls_entropy_update_seed_file() |
entropy_poll.h | Partial | Unsupported functions: mbedtls_null_entropy_poll(), mbedtls_platform_entropy_poll(), mbedtls_havege_poll(), mbedtls_hardclock_poll(), mbedtls_nv_seed_poll() |
error.h | Partial | Supported function: mbedtls_strerror() |
gcm.h | Yes | - |
havege.h | No | - |
hmac_drbg.h | Partial | Unsupported functions: mbedtls_hmac_drbg_write_seed_file(), mbedtls_hmac_drbg_update_seed_file() |
md2.h | No | - |
md4.h | No  | - |
md5.h | Yes | - |
md.h | Yes | - |
memory_buffer_Alloc.h | No | - |
net_sockets.h | Yes: | - |
oid.h | Yes | - |
padlock.h | No  | - |
pem.h | Yes | - |
pkcs11.h | No | - |
pkcs12.h | Yes | - |
pkcs5.h | Yes | - |
pk.h | Partial | Unsupported functions: mbedtls_pk_parse_keyfile(), mbedtls_pk_parse_public_keyfile(), mbedtls_pk_load_file() |
platform.h | Partial | Supported functions: mbedtls_platform_setup(), mbedtls_platform_teardown() |
ripemd160.h | No | - |
rsa.h | Yes | - |
sha1.h | Yes | - |
sha256.h | Yes | - |
sha512.h | Yes | - |
ssl_cache.h | Yes | - |
ssl_ciphersuites.h | Partial | Unsupported functions: mbedtls_ssl_ciphersuite_uses_dhe(), mbedtls_ssl_ciphersuite_uses_ecdhe(), mbedtls_ssl_ciphersuite_uses_server_signature() |
ssl_cookie.h | Yes | - |
ssl.h | Partial | Unsupported functions: mbedtls_ssl_conf_psk(), mbedtls_ssl_set_hs_psk(), mbedtls_ssl_conf_psk_cb(), mbedtls_ssl_conf_dh_param(), mbedtls_ssl_conf_dh_param_ctx(), mbedtls_ssl_conf_dhm_min_bitlen(), mbedtls_ssl_set_hs_ecjpake_password(), mbedtls_ssl_conf_arc4_support(), mbedtls_ssl_conf_truncated_hmac(), mbedtls_ssl_conf_cbc_record_splitting(), mbedtls_ssl_conf_renegotiation(), mbedtls_ssl_conf_renegotiation_enforced(), mbedtls_ssl_conf_renegotiation_period(), mbedtls_ssl_renegotiate() |
ssl_internal.h | Partial | Unsupported function: mbedtls_ssl_psk_derive_premaster() |
ssl_ticket.h | Yes | - |
threading.h | No  | - |
timing.h | No | - |
version.h | Yes | - |
x509_crl.h | Partial | Expiration checks rely on implicit calls to untrusted host process and not enclave secured time. Unsupported function: mbedtls_x509_crl_parse_file() |
x509_crt.h | Partial | Expiration checks rely on implicit calls to untrusted host process and not enclave secured time. Unsupported functions: mbedtls_x509_crl_parse_file(), mbedtls_x509_crt_parse_path() |
x509_csr.h | Partial | Expiration checks rely on implicit calls to untrusted host process and not enclave secured time. Unsupported function: mbedtls_x509_csr_parse_file() |
x509.h | Yes | - |
xtea.h | No | - |
