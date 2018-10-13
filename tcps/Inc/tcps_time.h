/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#include <stdint.h>

typedef int64_t __time64_t;

#ifndef _TIME_T_DEFINED_
# ifdef _USE_32BIT_TIME_T
typedef int32_t __time32_t;
typedef __time32_t time_t;
# else
typedef __time64_t time_t;
# endif
# define _TIME_T_DEFINED_
#endif
