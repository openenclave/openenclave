#ifndef __ELIBC_FLOAT_H
#define __ELIBC_FLOAT_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

/*
**==============================================================================
**
** Common:
**
**==============================================================================
*/

int __flt_rounds(void);

#define FLT_ROUNDS (__flt_rounds())

#define FLT_RADIX 2

#define FLT_TRUE_MIN 1.40129846432481707092e-45F
#define FLT_MIN 1.17549435082228750797e-38F
#define FLT_MAX 3.40282346638528859812e+38F
#define FLT_EPSILON 1.1920928955078125e-07F

#define FLT_MANT_DIG 24
#define FLT_MIN_EXP (-125)
#define FLT_MAX_EXP 128
#define FLT_HAS_SUBNORM 1

#define FLT_DIG 6
#define FLT_DECIMAL_DIG 9
#define FLT_MIN_10_EXP (-37)
#define FLT_MAX_10_EXP 38

#define DBL_TRUE_MIN 4.94065645841246544177e-324
#define DBL_MIN 2.22507385850720138309e-308
#define DBL_MAX 1.79769313486231570815e+308
#define DBL_EPSILON 2.22044604925031308085e-16

#define DBL_MANT_DIG 53
#define DBL_MIN_EXP (-1021)
#define DBL_MAX_EXP 1024
#define DBL_HAS_SUBNORM 1

#define DBL_DIG 15
#define DBL_DECIMAL_DIG 17
#define DBL_MIN_10_EXP (-307)
#define DBL_MAX_10_EXP 308

#define LDBL_HAS_SUBNORM 1
#define LDBL_DECIMAL_DIG DECIMAL_DIG

/*
**==============================================================================
**
** X86-64 specific
**
**==============================================================================
*/

#ifdef __FLT_EVAL_METHOD__
#define FLT_EVAL_METHOD __FLT_EVAL_METHOD__
#else
#define FLT_EVAL_METHOD 0
#endif

#define LDBL_TRUE_MIN 3.6451995318824746025e-4951L
#define LDBL_MIN     3.3621031431120935063e-4932L
#define LDBL_MAX     1.1897314953572317650e+4932L
#define LDBL_EPSILON 1.0842021724855044340e-19L

#define LDBL_MANT_DIG 64
#define LDBL_MIN_EXP (-16381)
#define LDBL_MAX_EXP 16384

#define LDBL_DIG 18
#define LDBL_MIN_10_EXP (-4931)
#define LDBL_MAX_10_EXP 4932

#define DECIMAL_DIG 21

__ELIBC_END

#endif /* __ELIBC_FLOAT_H */
