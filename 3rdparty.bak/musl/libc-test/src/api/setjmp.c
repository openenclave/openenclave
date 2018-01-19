#include <setjmp.h>
#define T(t) (t*)0;
static void f()
{
T(jmp_buf)
{void(*p)(jmp_buf,int) = longjmp;}
#ifdef setjmp
{int x = setjmp((jmp_buf){0});}
#else
{int(*p)(jmp_buf) = setjmp;}
#endif
#ifdef _POSIX_C_SOURCE
T(sigjmp_buf)
{void(*p)(sigjmp_buf,int) = siglongjmp;}
#ifdef sigsetjmp
{int x = sigsetjmp((sigjmp_buf){0}, 0);}
#else
{int(*p)(sigjmp_buf,int) = sigsetjmp;}
#endif
#endif
#if defined _XOPEN_SOURCE && defined OBSOLETE
{void(*p)(jmp_buf,int) = _longjmp;}
#ifdef _setjmp
{int x = _setjmp((jmp_buf){0});}
#else
{int(*p)(jmp_buf) = _setjmp;}
#endif
#endif
}
