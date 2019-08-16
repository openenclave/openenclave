// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_NEED_STDC_NAMES
#include <openenclave/bits/optee/opteeproperties.h>
#include <openenclave/enclave.h>

#define OE_TA_INFO_SECTION_NAME ".ta_info"
#define OE_TA_INFO_SECTION_BEGIN \
    OE_EXTERNC __attribute__((section(OE_TA_INFO_SECTION_NAME)))
#define OE_TA_INFO_SECTION_END

OE_TA_INFO_SECTION_BEGIN
const struct ta_info ta_info = {
    .rva = 0,
};
OE_TA_INFO_SECTION_END

const char trace_ext_prefix[] = "TA";
int trace_level = 4;

int tahead_get_trace_level(void)
{
    return trace_level;
}

uintptr_t tainfo_get_rva(void)
{
    return ta_info.rva;
}
