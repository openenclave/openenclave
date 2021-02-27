/*

  Copyright 2018 Intel Corporation

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <gmp.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#define LOG2_10 3.32192809488736218171

/* Use the Chudnovsky equation to rapidly estimate pi */

#define DIGITS_PER_ITERATION 14.1816 /* Roughly */

mpz_t c3, c4, c5;
int pi_init = 0;

void e_calc_pi(mpf_t* pi, uint64_t digits)
{
    uint64_t k, n;
    mp_bitcnt_t precision;
    static double bits = LOG2_10;
    mpz_t kf, kf3, threekf, sixkf, z1, z2, c4k, c5_3k;
    mpf_t C, sum, div, f2;

    n = (digits / DIGITS_PER_ITERATION) + 1;
    precision = (digits * bits) + 1;

    mpf_set_default_prec(precision);

    /* Re-initialize the pi variable to use our new precision */

    mpf_set_prec(*pi, precision);

    /*

      426880 sqrt(10005)    inf (6k)! (13591409+545140134k)
      ------------------- = SUM ---------------------------
      pi           k=0   (3k)!(k!)^3(-640320)^3k

      C / pi = SUM (6k)! * (c3 + c4*k) / (3k)!(k!)^3(c5)^3k

      C / pi = SUM f1 / f2

      pi = C / sum

    */

    mpz_inits(sixkf, z1, z2, kf, kf3, threekf, c4k, c5_3k, NULL);
    mpf_inits(C, sum, div, f2, NULL);

    /* Calculate 'C' */

    mpf_sqrt_ui(C, 10005);
    mpf_mul_ui(C, C, 426880);

    if (!pi_init)
    {
        /* Constants needed in 'sum'. */

        mpz_inits(c3, c4, c5, NULL);

        mpz_set_ui(c3, 13591409);
        mpz_set_ui(c4, 545140134);
        mpz_set_si(c5, -640320);

        pi_init = 1;
    }

    mpf_set_ui(sum, 0);

    for (k = 0; k < n; ++k)
    {
        /* Numerator */
        mpz_fac_ui(sixkf, 6 * k);
        mpz_mul_ui(c4k, c4, k);
        mpz_add(c4k, c4k, c3);
        mpz_mul(z1, c4k, sixkf);
        mpf_set_z(div, z1);

        /* Denominator */
        mpz_fac_ui(threekf, 3 * k);
        mpz_fac_ui(kf, k);
        mpz_pow_ui(kf3, kf, 3);
        mpz_mul(z2, threekf, kf3);
        mpz_pow_ui(c5_3k, c5, 3 * k);
        mpz_mul(z2, z2, c5_3k);

        /* Divison */

        mpf_set_z(f2, z2);
        mpf_div(div, div, f2);

        /* Sum */

        mpf_add(sum, sum, div);
    }

    mpf_div(*pi, C, sum);

    mpf_clears(div, sum, f2, C, NULL);
    mpz_clears(kf, kf3, threekf, sixkf, z1, z2, c4k, c5_3k, NULL);
    mpz_clears(c3, c4, c5, NULL);
}
