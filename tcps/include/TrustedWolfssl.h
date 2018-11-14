/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#if defined(_WIN32)
#undef _WIN32
#endif

#include <string.h>
#include <time.h>

#if defined(OE_USE_OPTEE)
#include <tee_api.h>
#include "optee/ctype_optee_t.h"
#else
unsigned long _lrotl(unsigned long val, int shift);
unsigned long _lrotr(unsigned long value, int shift);
#endif

#include "tcps_stdlib_t.h"
#include <openenclave/bits/stdio.h>
#include <openenclave/bits/timetypes.h>
#include "tcps_string_t.h"
