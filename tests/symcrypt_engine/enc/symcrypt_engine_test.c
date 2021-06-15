// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/* We do not have the SymCrypt engine available yet, defining a mock initializer
 * with the same function prototype and returns 1, mimicking the expected
 * behavior. */
int SYMCRYPT_ENGINE_Initialize()
{
    return 1;
}
