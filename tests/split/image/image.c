// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

int _start(void (*callback)(const char* msg))
{
    if (callback)
        (*callback)("hello from the isolated image");

    return 12345;
}
