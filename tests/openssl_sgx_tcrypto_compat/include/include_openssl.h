// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _INCLUDE_OPENSSL_H
#define _INCLUDE_OPENSSL_H

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "crypto/asn1.h"
#include "crypto/bn/bn_local.h"
#include "crypto/evp.h"
#include "crypto/evp/evp_local.h"
#include "crypto/hmac/hmac_local.h"
#include "crypto/rsa/rsa_local.h"
#include "crypto/x509/x509_local.h"

#define _Neg ((size_t)-1)

#endif //_INCLUDE_OPENSSL_H
