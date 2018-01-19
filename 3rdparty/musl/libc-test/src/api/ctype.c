#include <ctype.h>
#define T(t) (t*)0;
static void f()
{
{int(*p)(int) = isalnum;}
{int(*p)(int) = isalpha;}
{int(*p)(int) = isascii;}
{int(*p)(int) = isblank;}
{int(*p)(int) = iscntrl;}
{int(*p)(int) = isdigit;}
{int(*p)(int) = isgraph;}
{int(*p)(int) = islower;}
{int(*p)(int) = isprint;}
{int(*p)(int) = ispunct;}
{int(*p)(int) = isspace;}
{int(*p)(int) = isupper;}
{int(*p)(int) = isxdigit;}
{int(*p)(int) = toascii;}
{int(*p)(int) = tolower;}
{int(*p)(int) = toupper;}

#ifdef _POSIX_C_SOURCE
T(locale_t)
{int(*p)(int,locale_t) = isalnum_l;}
{int(*p)(int,locale_t) = isalpha_l;}
{int(*p)(int,locale_t) = isblank_l;}
{int(*p)(int,locale_t) = iscntrl_l;}
{int(*p)(int,locale_t) = isdigit_l;}
{int(*p)(int,locale_t) = isgraph_l;}
{int(*p)(int,locale_t) = islower_l;}
{int(*p)(int,locale_t) = isprint_l;}
{int(*p)(int,locale_t) = ispunct_l;}
{int(*p)(int,locale_t) = isspace_l;}
{int(*p)(int,locale_t) = isupper_l;}
{int(*p)(int,locale_t) = isxdigit_l;}
{int(*p)(int,locale_t) = tolower_l;}
{int(*p)(int,locale_t) = toupper_l;}
#endif
}
