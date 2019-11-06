// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <libc.h>
#include <locale.h>
#include <openenclave/enclave.h>
#include <string.h>

/* ATTN: should these assert? */

/* C or POSIX lconv structure */
static struct lconv posix_lconv = {
    .decimal_point = ".",
    .thousands_sep = "",
    .grouping = "",
    .int_curr_symbol = "",
    .currency_symbol = "",
    .mon_decimal_point = "",
    .mon_thousands_sep = "",
    .mon_grouping = "",
    .positive_sign = "",
    .negative_sign = "",
    .int_frac_digits = -1,
    .frac_digits = -1,
    .p_cs_precedes = -1,
    .p_sep_by_space = -1,
    .n_cs_precedes = -1,
    .n_sep_by_space = -1,
    .p_sign_posn = -1,
    .n_sign_posn = -1,
    .int_p_cs_precedes = -1,
    .int_p_sep_by_space = -1,
    .int_n_cs_precedes = -1,
    .int_n_sep_by_space = -1,
    .int_p_sign_posn = -1,
    .int_n_sign_posn = -1,
};

static const struct __locale_struct c_locale = {0};

locale_t uselocale(locale_t newloc)
{
    OE_UNUSED(newloc);
    return 0;
}

struct lconv* localeconv(void)
{
    return &posix_lconv;
}

void freelocale(locale_t loc)
{
    OE_UNUSED(loc);
}

char* setlocale(int category, const char* locale)
{
    OE_UNUSED(category);
    OE_UNUSED(locale);
    return NULL;
}

locale_t newlocale(int mask, const char* locale, locale_t loc)
{
    int builtin;
    OE_UNUSED(mask);

    /* Currently we will support basic C/POSIX locale */
    builtin = (locale[0] == 'C' && !locale[1]) || !strcmp(locale, "POSIX");

    if (builtin)
    {
        // if locale is already allocated, we need to modify it
        // according to the mask value. Currently we are supporting
        // builtin locales only. So locale modify has no effect. Just return
        // the loc itself. If loc is not a valid locale ptr,
        // then behavior is undefined
        if (loc)
            return loc;
        else
            // if loc is NULL/0, then we will return a dummy C locale reference
            return (locale_t)&c_locale;
    }
    else
    {
        // Enclave doesn't support any locales other than builtin for the time
        // being.
        return 0;
    }
}
