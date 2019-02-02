// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <bits/intstr.h>
#include <openenclave/internal/print.h>

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

#define FLAG_NONE (uint32_t)(1 << 0)
#define FLAG_MINUS (uint32_t)(1 << 1)
#define FLAG_PLUS (uint32_t)(1 << 2)
#define FLAG_SPACE (uint32_t)(1 << 3)
#define FLAG_POUND (uint32_t)(1 << 4)
#define FLAG_ZERO (uint32_t)(1 << 5)

#define ELIBC_STRLEN(STR) (sizeof(STR) - 1)
#define ELIBC_STRLIT(STR) STR, ELIBC_STRLEN(STR)

typedef struct _elibc_out elibc_out_t;

struct _elibc_out
{
    size_t (*write)(elibc_out_t* out, const void* buf, size_t count);
};

enum type
{
    TYPE_none,
    TYPE_s,
    TYPE_c,
    TYPE_p,
    TYPE_o,
    TYPE_u,
    TYPE_d,
    TYPE_i,
    TYPE_x,
    TYPE_X,
    TYPE_zu,
    TYPE_zd,
    TYPE_zi,
    TYPE_lu,
    TYPE_ld,
    TYPE_li,
    TYPE_lx,
    TYPE_llu,
    TYPE_lld,
    TYPE_lli,
    TYPE_llx,
};

struct placeholder
{
    uint32_t flags;
    int width;
    int precision;
    enum type type;
    char conversion;
};

/* Syntax: %flags width [ . precision ] type conversion */
static const char* _parse_placeholder(
    const char* p,
    struct placeholder* ph,
    elibc_va_list ap)
{
    ph->flags = FLAG_NONE;
    ph->width = ELIBC_INT_MAX;
    ph->precision = ELIBC_INT_MAX;
    ph->type = TYPE_none;

    if (*p++ != '%')
        return NULL;

    /* Parse the flags if any */
    for (bool more = true; more;)
    {
        switch (*p)
        {
            case '-':
                ph->flags |= FLAG_MINUS;
                p++;
                break;
            case '+':
                ph->flags |= FLAG_PLUS;
                p++;
                break;
            case ' ':
                ph->flags |= FLAG_SPACE;
                p++;
                break;
            case '#':
                ph->flags |= FLAG_POUND;
                p++;
                break;
            case '0':
                ph->flags |= FLAG_ZERO;
                p++;
                break;
            default:
                more = false;
                break;
        }
    }

    /* Parse the width */
    if (oe_isdigit(*p))
    {
        char* end = NULL;
        unsigned long int ul = elibc_strtoul(p, &end, 10);
        if (!end || ul > ELIBC_INT_MAX)
            return NULL;

        ph->width = (int)ul;
        p = end;
    }
    else if (*p == '*')
    {
        ph->width = elibc_va_arg(ap, int);
        p++;
    }

    /* Parse the dot and the precision */
    if (*p == '.')
    {
        p++;

        /* Parse the precision */
        if (oe_isdigit(*p))
        {
            char* end = NULL;
            unsigned long int ul = elibc_strtoul(p, &end, 10);
            if (!end || ul > ELIBC_INT_MAX)
                return NULL;

            ph->precision = (int)ul;
            p = end;
        }
        else if (*p == '*')
        {
            ph->precision = elibc_va_arg(ap, int);
            p++;
        }
    }

    /* Parse the type */
    if (p[0] == 's')
    {
        ph->type = TYPE_s;
        ph->conversion = 's';
        p++;
    }
    else if (p[0] == 'c')
    {
        ph->type = TYPE_c;
        ph->conversion = 'c';
        /* Ignore precision on %c */
        ph->precision = ELIBC_INT_MAX;
        ph->flags &= ~FLAG_ZERO;
        p++;
    }
    else if (p[0] == 'o')
    {
        ph->type = TYPE_o;
        ph->conversion = 'o';
        p++;
    }
    else if (p[0] == 'u')
    {
        ph->type = TYPE_u;
        ph->conversion = 'u';
        p++;
    }
    else if (p[0] == 'd')
    {
        ph->type = TYPE_d;
        ph->conversion = 'd';
        p++;
    }
    else if (p[0] == 'i')
    {
        ph->type = TYPE_i;
        ph->conversion = 'i';
        p++;
    }
    else if (p[0] == 'x')
    {
        ph->type = TYPE_x;
        ph->conversion = 'x';
        p++;
    }
    else if (p[0] == 'X')
    {
        ph->type = TYPE_X;
        ph->conversion = 'X';
        p++;
    }
    else if (p[0] == 'l' && p[1] == 'u')
    {
        ph->type = TYPE_lu;
        ph->conversion = 'u';
        p += 2;
    }
    else if (p[0] == 'l' && p[1] == 'l' && p[2] == 'u')
    {
        ph->type = TYPE_llu;
        ph->conversion = 'u';
        p += 3;
    }
    else if (p[0] == 'l' && p[1] == 'd')
    {
        ph->type = TYPE_ld;
        ph->conversion = 'd';
        p += 2;
    }
    else if (p[0] == 'l' && p[1] == 'l' && p[2] == 'd')
    {
        ph->type = TYPE_lld;
        ph->conversion = 'd';
        p += 3;
    }
    else if (p[0] == 'l' && p[1] == 'i')
    {
        ph->type = TYPE_li;
        ph->conversion = 'i';
        p += 2;
    }
    else if (p[0] == 'l' && p[1] == 'l' && p[2] == 'i')
    {
        ph->type = TYPE_lli;
        ph->conversion = 'i';
        p += 3;
    }
    else if (p[0] == 'l' && p[1] == 'x')
    {
        ph->type = TYPE_lx;
        ph->conversion = 'x';
        p += 2;
    }
    else if (p[0] == 'l' && p[1] == 'X')
    {
        ph->type = TYPE_lx;
        ph->conversion = 'X';
        p += 2;
    }
    else if (p[0] == 'l' && p[1] == 'l' && p[2] == 'x')
    {
        ph->type = TYPE_llx;
        ph->conversion = 'x';
        p += 3;
    }
    else if (p[0] == 'l' && p[1] == 'l' && p[2] == 'X')
    {
        ph->type = TYPE_llx;
        ph->conversion = 'X';
        p += 3;
    }
    else if (p[0] == 'z' && p[1] == 'u')
    {
        ph->type = TYPE_zu;
        ph->conversion = 'u';
        p += 2;
    }
    else if (p[0] == 'z' && p[1] == 'd')
    {
        ph->type = TYPE_zd;
        ph->conversion = 'd';
        p += 2;
    }
    else if (p[0] == 'z' && p[1] == 'i')
    {
        ph->type = TYPE_zi;
        ph->conversion = 'i';
        p += 2;
    }
    else if (p[0] == 'p')
    {
        ph->type = TYPE_p;
        ph->conversion = 'p';
        p += 1;
    }
    else
    {
        return NULL;
    }

    return p;
}

static void _str_toupper(char* s)
{
    while (*s)
    {
        *s = (char)oe_toupper(*s);
        s++;
    }
}

static size_t _fill(elibc_out_t* out, char c, size_t count)
{
    size_t n = 0;

    for (size_t i = 0; i < count; i++)
        n += out->write(out, &c, 1);

    return n;
}

static size_t _prefix(elibc_out_t* out, struct placeholder* ph)
{
    size_t n = 0;

    if (ph->flags & FLAG_POUND)
    {
        switch (ph->conversion)
        {
            case 'x':
            {
                n += out->write(out, ELIBC_STRLIT("0x"));
                break;
            }
            case 'X':
            {
                n += out->write(out, ELIBC_STRLIT("0X"));
                break;
            }
            case 'o':
            {
                n += out->write(out, ELIBC_STRLIT("0"));
                break;
            }
        }
    }

    return n;
}

/* return the number of characters formatted */
static size_t _format(
    elibc_out_t* out,
    const char* buf,
    size_t len,
    struct placeholder* ph)
{
    size_t nwidth = 0;
    size_t nprecision = 0;
    char pad = ' ';
    size_t n = 0;

    if (ph->width != ELIBC_INT_MAX && (size_t)ph->width > len)
        nwidth = (size_t)ph->width - len;

    if (ph->precision != ELIBC_INT_MAX && (size_t)ph->precision > len)
        nprecision = (size_t)ph->precision - len;

    if (nprecision > nwidth)
        nwidth = 0;
    else
        nwidth -= nprecision;

    /* Handle zero flag */
    if (ph->flags & FLAG_ZERO)
        pad = '0';

    if (ph->type == TYPE_s && len > (size_t)ph->precision)
        len = (size_t)ph->precision;

    /* Prepend space to positive numbers */
    if (ph->conversion == 'd' && (ph->flags & FLAG_SPACE) && buf[0] != '-')
    {
        n += out->write(out, " ", 1);

        if (nwidth > 0)
            nwidth--;
    }

    if (ph->flags & FLAG_MINUS)
    {
        /* left justified */
        n += _prefix(out, ph);
        n += _fill(out, '0', nprecision);
        n += out->write(out, buf, len);
        n += _fill(out, pad, nwidth);
    }
    else
    {
        /* right justified */
        n += _fill(out, pad, nwidth);
        n += _prefix(out, ph);
        n += _fill(out, '0', nprecision);
        n += out->write(out, buf, len);
    }

    return n;
}

static int _vprintf(elibc_out_t* out, const char* fmt, elibc_va_list ap)
{
    const char* p = fmt;
    size_t n = 0;

    while (*p)
    {
        char buf[64];

        if (p[0] == '%' && p[1] == '%')
        {
            n += out->write(out, "%%", 1);
            p += 2;
        }
        else if (*p == '%')
        {
            struct placeholder ph;
            const char* s = NULL;
            size_t sn = 0;
            elibc_intstr_buf_t is;

            if (!(p = _parse_placeholder(p, &ph, ap)))
            {
                return -1;
            }

            switch (ph.type)
            {
                case TYPE_s:
                {
                    if ((s = elibc_va_arg(ap, const char*)))
                    {
                        sn = oe_strlen(s);
                    }
                    else
                    {
                        s = "(null)";
                        sn = 6;
                    }
                    break;
                }
                case TYPE_c:
                {
                    buf[0] = (char)elibc_va_arg(ap, int);
                    buf[1] = '\0';
                    s = buf;
                    sn = sizeof(char);
                    break;
                }
                case TYPE_o:
                {
                    const uint32_t x = elibc_va_arg(ap, uint32_t);
                    s = elibc_uint64_to_octstr(&is, x, &sn);
                    break;
                }
                case TYPE_u:
                {
                    const uint32_t x = elibc_va_arg(ap, uint32_t);
                    s = elibc_uint64_to_decstr(&is, x, &sn);
                    break;
                }
                case TYPE_d:
                case TYPE_i:
                {
                    const int32_t x = elibc_va_arg(ap, int32_t);
                    s = elibc_int64_to_decstr(&is, x, &sn);
                    break;
                }
                case TYPE_x:
                {
                    const uint32_t x = elibc_va_arg(ap, uint32_t);
                    s = elibc_uint64_to_hexstr(&is, x, &sn);
                    break;
                }
                case TYPE_X:
                {
                    const uint32_t x = elibc_va_arg(ap, uint32_t);
                    s = elibc_uint64_to_hexstr(&is, x, &sn);
                    _str_toupper((char*)s);
                    break;
                }
                case TYPE_lu:
                case TYPE_llu:
                {
                    const uint64_t x = elibc_va_arg(ap, uint64_t);
                    s = elibc_uint64_to_decstr(&is, x, &sn);
                    break;
                }
                case TYPE_ld:
                case TYPE_li:
                case TYPE_lld:
                case TYPE_lli:
                {
                    const int64_t x = elibc_va_arg(ap, int64_t);
                    s = elibc_int64_to_decstr(&is, x, &sn);
                    break;
                }
                case TYPE_lx:
                case TYPE_llx:
                {
                    const uint64_t x = elibc_va_arg(ap, uint64_t);
                    s = elibc_uint64_to_hexstr(&is, x, &sn);

                    if (ph.conversion == 'X')
                        _str_toupper((char*)s);

                    break;
                }
                case TYPE_zu:
                {
                    const size_t x = elibc_va_arg(ap, size_t);
                    s = elibc_uint64_to_decstr(&is, x, &sn);
                    break;
                }
                case TYPE_zd:
                case TYPE_zi:
                {
                    const ssize_t x = elibc_va_arg(ap, ssize_t);
                    s = elibc_int64_to_decstr(&is, x, &sn);
                    break;
                }
                case TYPE_p:
                {
                    const uint64_t x = (uint64_t)elibc_va_arg(ap, void*);
                    s = elibc_uint64_to_hexstr(&is, x, &sn);
                    break;
                }
                default:
                {
                    return -1;
                }
            }

            n += _format(out, s, sn, &ph);
        }
        else
        {
            n += out->write(out, p, 1);
            p++;
        }
    }

    return (int)n;
}

typedef struct _elibc_out_str
{
    elibc_out_t base;
    char* str;
    size_t size;
    size_t off;
} elibc_out_str_t;

/* Not POSIX compliant write since this method does not return errno */
static size_t _write(elibc_out_t* out_, const void* buf, size_t count)
{
    elibc_out_str_t* out = (elibc_out_str_t*)out_;

    if (out->off < out->size)
    {
        /* Leave an extra byte for the zero-terminator */
        size_t rem = out->size - out->off - 1;
        size_t n;

        if (rem < count)
            n = rem;
        else
            n = count;

        memcpy(&out->str[out->off], buf, n);
        out->str[out->off + n] = '\0';
    }

    out->off += count;

    return count;
}

static void _elibc_out_str_init(elibc_out_str_t* out, char* str, size_t size)
{
    out->base.write = _write;
    out->str = str;
    out->size = size;
    out->off = 0;
}

/*
**==============================================================================
**
** Public definitions:
**
**==============================================================================
*/

//
// Produce output according to a given format string.
//
// This function is similar to vsnprintf() but has no support for floating
// point types.
//
// @param str Write output to this string
// @param size The size of **str** parameter.
// @param fmt The limited printf style format.
//
// @returns The number of characters that would be written excluding the
// zero-terminator. If this value is greater or equal to **size**, then the
// string was truncated.
//
//
int elibc_vsnprintf(char* str, size_t size, const char* fmt, elibc_va_list ap)
{
    elibc_out_str_t out;

    if (!str && size != 0)
        return -1;

    _elibc_out_str_init(&out, str, size);

    return _vprintf(&out.base, fmt, ap);
}

//
// Produce output according to a given format string.
//
// This function is similar to snprintf() but has limited support for format
// types. See elibc_vsnprintf() for details on these limits.
//
// @param str Write output to this string.
// @param size The size of **str** parameter.
// @param fmt The limited printf style format.
//
// @returns The number of characters that would be written excluding the
// zero-terminator. If this value is greater or equal to **size**, then the
// string was truncated.
//
int elibc_snprintf(char* str, size_t size, const char* fmt, ...)
{
    elibc_va_list ap;
    elibc_va_start(ap, fmt);
    int n = oe_vsnprintf(str, size, fmt, ap);
    elibc_va_end(ap);
    return n;
}

int elibc_vprintf(const char* fmt, elibc_va_list ap_)
{
    char buf[256];
    char* p = buf;
    int n;
    char* new_buf = NULL;

    /* Try first with a fixed-length scratch buffer */
    {
        elibc_va_list ap;
        elibc_va_copy(ap, ap_);
        n = oe_vsnprintf(buf, sizeof(buf), fmt, ap);
        elibc_va_end(ap);

        if (n < 0)
            goto done;

        if ((size_t)n < sizeof(buf))
        {
            oe_host_write(0, p, (size_t)-1);
            goto done;
        }
    }

    /* If string was truncated, retry with correctly sized buffer */
    {
        if (!(new_buf = (char*)oe_malloc((size_t)n + 1)))
            goto done;

        p = new_buf;

        elibc_va_list ap;
        elibc_va_copy(ap, ap_);
        n = oe_vsnprintf(p, (size_t)n + 1, fmt, ap);
        elibc_va_end(ap);

        if (n < 0)
            goto done;

        oe_host_write(0, p, (size_t)-1);
    }

done:

    if (new_buf)
        oe_free(new_buf);

    return n;
}

int elibc_printf(const char* format, ...)
{
    elibc_va_list ap;
    int n;

    elibc_va_start(ap, format);
    n = elibc_vprintf(format, ap);
    elibc_va_end(ap);

    return n;
}
