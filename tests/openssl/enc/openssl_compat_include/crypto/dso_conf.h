// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*
 * Open Enclave compatibility override for OpenSSL test/simpledynamic.c.
 *
 * For enclave test binaries we cannot use host dlopen/dlsym/dlclose. Force
 * DSO_NONE so simpledynamic compiles without dynamic loader entry points.
 */

#ifndef OSSL_CRYPTO_DSO_CONF_H
#define OSSL_CRYPTO_DSO_CONF_H
#pragma once

#ifndef DSO_NONE
#define DSO_NONE 1
#endif
#define DSO_EXTENSION ".so"

#endif
