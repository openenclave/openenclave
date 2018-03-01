#include <locale.h>

/* ATTN: should these assert? */

static struct lconv default_lconv;

locale_t uselocale(locale_t newloc)
{
    return 0;
}

struct lconv* localeconv(void)
{
    return &default_lconv;
}

void freelocale(locale_t loc)
{
}

char* setlocale(int category, const char* locale)
{
    return NULL;
}

locale_t newlocale(int category_mask, const char* locale, locale_t base)
{
    return 0;
}
