// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "all_t.h"

uint8_t g_enabled[4] = {true, true, true, true};

void configure_type(const char* type_name, type_enum_t t)
{
    uint64_t enc_size = get_enclave_sizeof(t);
    uint64_t host_size = 0;
    OE_TEST(get_host_sizeof(&host_size, t) == OE_OK);

    printf(
        "%s: size in host = %lu, size in enclave = %lu.",
        type_name,
        host_size,
        enc_size);
    g_enabled[t] = (enc_size == host_size);
    printf(
        " Testing of %s is %s\n",
        type_name,
        g_enabled[t] ? "enabled" : "disabled");
}

void configure(uint8_t enabled[3])
{
    configure_type("wchar_t", TYPE_WCHAR_T);
    configure_type("long", TYPE_LONG);
    configure_type("unsigned long", TYPE_UNSIGNED_LONG);
    configure_type("long double", TYPE_LONG_DOUBLE);
    memcpy(enabled, g_enabled, sizeof(g_enabled));
}
