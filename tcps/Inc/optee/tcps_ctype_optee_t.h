/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef TRUSTED_CODE
# error tcps_ctype_optee_t.h should only be included with TRUSTED_CODE
#endif
#ifndef USE_OPTEE
# error tcps_ctype_optee_t.h should only be included with USE_OPTEE
#endif
#include "tcps_t.h"

int tolower(int c);
int toupper(int const c);

int isspace(int c); 
int isupper(int c); 
int islower(int c);
int isdigit(int c); 
int isxdigit(int c); 
int isalnum(int c);
int isalpha(int c);
