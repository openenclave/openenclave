#ifndef _stdc_args_h
#define _stdc_args_h

#include <stddef.h>

typedef struct _TestArgs
{
    int ret;
    bool caught;
    bool dynamicCastWorks;
    size_t numConstructions;
} TestArgs;

#endif /* _stdc_args_h */
