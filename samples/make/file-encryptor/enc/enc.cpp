// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <algorithm>
#include <cstdio>
#include "encryptor.h"
#include "../args.h"


template <typename T>
void checkArgs(T* args)
{
  if (!oe_is_outside_enclave(args, sizeof(T)))
     oe_host_printf("Enclave:Arguments are not in shared memory (%p) size=0x%lx\n", 
                    (char*)args, sizeof(T));    
}


// the enclave object
static Encryptor encryptor;

#define DISPATCH(x) \
  checkArgs(args); \
  encryptor.x(args); 
 
/*
  try \
  { \
    e.x(args); \
  } \
  catch (const std::exception& ex) \
  { \
    Log<Level::FATAL>() << "Unhandled exception in " << __FUNCTION__ << ": " \
                        << ex.what() << std::endl; \
  } \
  catch (...) \
  { \
    Log<Level::FATAL>() << "Unhandled non-std exception in " << __FUNCTION__ \
                        << std::endl; \
  }
*/

// OE calls:wq!
OE_ECALL void set_password(PasswordArgs* args)
{
   oe_host_printf("Enclave:set_password called with args = (%s)\n", (char*)args);
   DISPATCH(set_password);
}

OE_ECALL void initialize_encryptor(EncryptArgs* args)
{
   oe_host_printf("Enclave:initialize_encryption\n");
   DISPATCH(initialize);
}

OE_ECALL void encryt_block(EncryptBlockArgs* args)
{
   oe_host_printf("Enclave:encryt_block\n");
   DISPATCH(encryt_block);
}

OE_ECALL void close_encryption(CloseEncryptorArgs* args)
{
   oe_host_printf("Enclave:close_encryption\n");
   DISPATCH(close);
}
