#include <openenclave/enclave.h>
#include "pingpong_t.h"

OE_EXTERNC void Ping(const char* in, char* out)
{
    Pong(in, out);
}
