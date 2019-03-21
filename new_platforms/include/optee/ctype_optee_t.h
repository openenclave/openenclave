/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_ENCLAVE_H
# include <openenclave/enclave.h>
#endif
#ifndef OE_USE_OPTEE
# error tcps_ctype_optee_t.h should only be included with OE_USE_OPTEE
#endif

#ifndef _CTYPE_H
int tolower(int c);
int toupper(int const c);

int isspace(int c); 
int isupper(int c); 
int islower(int c);
int isdigit(int c); 
int isxdigit(int c); 
int isalnum(int c);
int isalpha(int c);
#endif  // _CTYPE_H
