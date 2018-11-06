/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_ENCLAVE_H
# include <openenclave/enclave.h>
#endif

#ifdef USE_OPTEE
# ifdef BUFSIZ
#  undef BUFSIZ
# endif
# define BUFSIZ 1024
#ifdef SIMULATE_TEE
__declspec(noreturn)
#endif
void exit(int status);
#endif

char *getenv(const char *varname);

typedef int pid_t;
pid_t getpid(void);
