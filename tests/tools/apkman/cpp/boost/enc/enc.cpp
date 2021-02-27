// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <cstdio>
#include "test_t.h"

void boost_test();

int enc_main(int argc, char** argv)
{
    OE_UNUSED(argc);
    OE_UNUSED(argv);
    boost_test();
    return 0;
}

// Fix OE's locale implementation which returns NULL.
// Default locale is C.
#include <locale.h>
static char _locale[256] = "C";
extern "C" char* setlocale(int category, const char* locale)
{
    OE_UNUSED(category);
    if (locale == NULL)
        return _locale;
    sprintf(_locale, "%s", locale);
    return _locale;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
