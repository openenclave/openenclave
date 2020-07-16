// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

void _start(void (*callback)(const char* msg))
{
    if (callback)
        (*callback)("hello from isolated image");
}
