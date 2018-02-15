#ifndef _OE_TESTS_H
#define _OE_TESTS_H

#include <openenclave/defs.h>
#include <openenclave/types.h>
#include <stdio.h>

OE_EXTERNC_BEGIN

#define OE_TEST(COND)                                                                \
    do                                                                               \
    {                                                                                \
        if (!(COND))                                                                 \
        {                                                                            \
            fprintf(stderr, "Test failed: %s(%u): %s\n", __FILE__, __LINE__, #COND); \
            exit(1);                                                                 \
        }                                                                            \
    } while (0)

/*
 * Return flags to pass to OE_CreateEnclave() based on the OE_SIMULATION
 * environment variable.
 */
uint32_t OE_GetCreateFlags(void);

OE_EXTERNC_END

#endif /* _OE_TESTS_H */
