/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_ENCLAVE_H
# include <openenclave/enclave.h>
#endif

#ifdef OE_USE_OPTEE
# ifdef BUFSIZ
#  undef BUFSIZ
# endif
# define BUFSIZ 1024
#ifdef OE_SIMULATE_OPTEE
__declspec(noreturn)
#endif
void exit(int status);
#endif

char *getenv(const char *varname);

typedef int pid_t;
pid_t getpid(void);
