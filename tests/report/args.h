#ifndef _new_args_h
#define _new_args_h

#include <__openenclave/sgxtypes.h>

typedef struct _Args
{
    /* Input */
    SGX_TargetInfo targetInfo;
    SGX_ReportData reportData;

    /* Output */
    SGX_Report report;

    /* Return result */
    OE_Result result;
}
Args;

#endif /* _new_args_h */
