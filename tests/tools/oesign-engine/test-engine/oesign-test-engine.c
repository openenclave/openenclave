// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
//
// oesign-test-engine: minimal engine with predictable output to test oesign engine support

#include <openssl/engine.h>

static int bind(ENGINE *e, const char *id)
{
  (void)e;
  (void)id;
  return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
