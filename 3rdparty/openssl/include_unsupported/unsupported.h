// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_OPENSSL_UNSUPPORTED_H
#define _OE_OPENSSL_UNSUPPORTED_H

#if !defined(OE_OPENSSL_SUPPRESS_UNSUPPORTED)

#if defined(__cplusplus)
#define OE_OPENSSL_EXTERN_C_BEGIN \
    extern "C"                    \
    {
#define OE_OPENSSL_EXTERN_C_END }
#else
#define OE_OPENSSL_EXTERN_C_BEGIN
#define OE_OPENSSL_EXTERN_C_END
#endif

#if defined(__GNUC__)
#define OE_OPENSSL_UNSUPPORTED(MSG) __attribute__((deprecated(MSG)))
#else
#define OE_OPENSSL_UNSUPPORTED(MSG)
#endif
#define OE_OPENSSL_RAISE_ERROR(NAME) (OE_OPENSSL_UNSUPPORTED_ERROR, NAME)

// clang-format off
#define OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION \
    "The function may be unsafe inside an enclave as it causes the enclave to read " \
    "files from an untrusted host. Please refer to the following link for security guidance.\n\n" \
    "https://github.com/openenclave/openenclave/blob/master/docs/OpenSSLSupport.md#security-guidance-for-using-openssl-apismacros" \
    "\n\nTo use the function anyway, add the -DOE_OPENSSL_SUPPRESS_UNSUPPORTED option when compiling the program."
#define OE_UNSUPPORTED_ENCLAVE_OPENSSL_MACRO \
    "The macro may be unsafe inside an enclave as it causes the enclave to read " \
    "files from an untrusted host. Please refer to the following link for security guidance.\n\n" \
    "https://github.com/openenclave/openenclave/blob/master/docs/OpenSSLSupport.md#security-guidance-for-using-openssl-apismacros" \
    "\n\nTo use the macro anyway, add the -DOE_OPENSSL_SUPPRESS_UNSUPPORTED option when compiling the program."
// clang-format on

#endif /* !defined(OE_OPENSSL_SUPPRESS_UNSUPPORTED) */
#endif /* _OE_OPENSSL_UNSUPPORTED_H */
