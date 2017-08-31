#include <openenclave.h>
#include <cstdio>
#include <algorithm>
#include "../args.h"

using namespace std;

OE_ECALL void Sort(void* args_)
{
    Args* args = (Args*)args_;

    if (args)
    {
        sort(args->data, args->data + args->size);
    }
}
