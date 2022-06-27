// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>

int oesign(
    const char* enclave,
    const char* conffile,
    const char* keyfile,
    const char* digest_signature,
    const char* output_file,
    const char* x509,
    const char* engine_id,
    const char* engine_load_path,
    const char* key_id);

int main()
{
    oesign(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    return 0;
}
