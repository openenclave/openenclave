/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef TRUSTED_CODE
# error TCPS-SDK\include\optee\Trusted headers should only be included with TRUSTED_CODE
#endif
#include <stdint.h>

#ifndef _SSIZE_T_DEFINED_
typedef intptr_t ssize_t;
#endif
