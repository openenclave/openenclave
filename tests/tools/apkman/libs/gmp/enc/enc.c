// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include "test_t.h"

#include <stdio.h>
#include <string.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "gmp.h"

void fact(int n)
{
    int i;
    mpz_t p;

    mpz_init_set_ui(p, 1); /* p = 1 */
    for (i = 1; i <= n; ++i)
    {
        mpz_mul_ui(p, p, i); /* p = p * i */
    }
    printf("%d!  =  ", n);
    mpz_out_str(stdout, 10, p);
    mpz_clear(p);
    printf("\n");
}

void e_calc_pi(mpf_t* pi, uint64_t digits);

int enc_main(int argc, char** argv)
{
    int number;
    int pi_digits;
    if (argc != 3)
    {
        printf("Usage: %s <number> <pi-digits>\n", argv[0]);
        return -1;
    }

    number = atoi(argv[1]);
    assert(number >= 0);

    pi_digits = atoi(argv[2]);
    assert(pi_digits >= 6);

    fact(number);

    mpf_t pi;
    mpf_init(pi);
    e_calc_pi(&pi, pi_digits);
    printf("pi (%d digits) = ", pi_digits);
    mpf_out_str(stdout, 10, pi_digits, pi);
    printf("\n");
    mpf_clear(pi);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
