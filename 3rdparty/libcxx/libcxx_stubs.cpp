#include <pthread.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <wchar.h>

/* pthread.h */
namespace std
{
    int pthread_create(
        pthread_t* thread,
        const pthread_attr_t* attr,
        void* (*start_routine)(void* arg),
        void* arg)
    {
        assert("pthread_create(): panic" == NULL);
    }

    int pthread_join(pthread_t thread, void** ret)
    {
        assert("pthread_join(): panic" == NULL);
    }

    int pthread_detach(pthread_t thread)
    {
        assert("pthread_detach(): panic" == NULL);
    }

    int sched_yield(void)
    {
        assert("sched_yield(): panic" == NULL);
    }
}

/* locale.h */
namespace std
{
    locale_t __cloc(void)
    {
        return 0;
    }

    locale_t uselocale(locale_t newloc)
    {
        return 0;
    }

    struct lconv *localeconv(void)
    {
        return 0;
    }

    locale_t newlocale(
        int category_mask, const char *locale, locale_t base)
    {
        return 0;
    }

    void freelocale(locale_t loc)
    {
    }

    char *setlocale(int category, const char *locale)
    {
        return 0;
    }
}

/* string.h */
namespace std
{
    size_t strxfrm_l(char *dest, const char *src, size_t n, locale_t loc)
    {
        return strxfrm(dest, src, n);
    }

    int strcoll_l(const char *s1, const char *s2, locale_t loc)
    {
        return strcoll(s1, s2);
    }
}

/* wchar.h */
namespace std
{
    size_t wcsxfrm_l(
        wchar_t *dest, const wchar_t *src, size_t n, locale_t loc)
    {
        return wcsxfrm(dest, src, n);
    }

    int wcscoll_l(const wchar_t *s1, const wchar_t *s2, locale_t loc)
    {
        return wcscoll(s1, s2);
    }
}

/* time.h */
namespace std
{
    size_t strftime_l(char *s, size_t max, const char *format, 
        const struct tm *tm, locale_t loc)
    {
        return strftime(s, max, format, tm);
    }
}

/* stlib.h */
namespace std
{
    long long int strtoll_l(const char *nptr, char **endptr, int base, 
        locale_t loc)
    {
        return strtoll(nptr, endptr, base);
    }

    unsigned long long int strtoull_l(const char *nptr, char **endptr, 
        int base, locale_t loc)
    {
        return strtoull(nptr, endptr, base);
    }

    unsigned int arc4random(void)
    {
        return (unsigned int)::rand();
    }
}

/* stdio.h */
namespace std
{
    int getc(FILE *stream)
    {
        assert("getc(): panic" == NULL);
        return -1;
    }

    int ungetc(int c, FILE *stream)
    {
        assert("ungetc(): panic" == NULL);
        return -1;
    }

    size_t fwrite(
        const void *ptr, size_t size, size_t nmemb, FILE *stream)
    {
        assert("fwrite(): panic" == NULL);
        return 0;
    }

    int fflush(FILE *stream)
    {
        assert("fflush(): panic" == NULL);
        return -1;
    }
}
