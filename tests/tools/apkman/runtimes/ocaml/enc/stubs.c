// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* secure_getenv()
{
    return NULL;
}

ssize_t readlink(const char* pathname, char* buf, size_t bufsiz)
{
    OE_UNUSED(pathname);
    OE_UNUSED(buf);
    OE_UNUSED(bufsiz);
    sprintf(buf, "ocaml_enc");
    return (ssize_t)strlen(buf);
}

int sigsetjmp(sigjmp_buf b, int mask)
{
    // TODO: signal mask
    OE_UNUSED(mask);
    return setjmp(*(jmp_buf*)(void*)b);
}

void siglongjmp(sigjmp_buf b, int ret)
{
    longjmp(*(jmp_buf*)(void*)b, ret);
}
