// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _TESTS_CRYPTO_HASH_H
#define _TESTS_CRYPTO_HASH_H

#include <openenclave/internal/sha.h>

/* Upper case alphabet */
extern const char* ALPHABET;

/* Hash of ALPHABET string above */
extern OE_SHA256 ALPHABET_HASH;

/* Key for the HMAC calculation. */
extern unsigned char ALPHABET_KEY[];
extern size_t ALPHABET_KEY_SIZE;

/* HMAC value. */
extern OE_SHA256 ALPHABET_HMAC;

#endif /* _TESTS_CRYPTO_HASH_H */
