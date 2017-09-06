#ifndef _OE_TESTS_H
#define _OE_TESTS_H

#include <stdio.h>
#include <openenclave/defs.h>

#define OE_TEST(COND) \
    do \
    { \
        if (!(COND)) \
        { \
            fprintf(stderr, \
                "Test failed: %s(%u): %s\n", __FILE__, __LINE__, #COND); \
            exit(1); \
        } \
    } \
    while (0)

#endif /* _OE_TESTS_H */
