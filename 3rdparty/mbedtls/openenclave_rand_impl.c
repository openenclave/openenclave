#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/entropy_poll.h"

#ifndef _rdseed_step
#define _rdseed_step(x) ({ unsigned char err; asm volatile("rdseed %0; setc %1":"=r"(*x), "=qm"(err)); err; })
#endif

#define RDSEED_MAX_RETRIES 50

int rdseed_get_64(uint64_t* output, int retries)
{
    int try = 0;

    while( try < retries ) {
        if( _rdseed_step( output ) == 0 ) {
            return 0;
        } 

        try++;
    }

    return -1;
}

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    // @TODO validate that RDSEED is available via CPUID and we're running on a 64bit platform
    // Do we need support for 32 bit hosts? Only difference is we get 4 bytes at a time instead of 8 from RDSEED
    if( output == NULL ) {
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    // We need len bytes and we get 64 bits = 8 bytes at a time
    size_t desiredSuccesses = len >> 3;
    *olen = 0;
    uint64_t* out = (uint64_t*) output;

    for(size_t i = 0; i < desiredSuccesses; i++) {
        int res = rdseed_get_64(&out[i], RDSEED_MAX_RETRIES);
        if(res != 0) {
            return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
        }
        *olen += 8;
    }

    return 0;
}