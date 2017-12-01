#ifdef X_NDBM
#include <ndbm.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(size_t)
T(mode_t)
T(DBM)
{
datum x;
F(void*, dptr)
F(size_t, dsize)
}
C(DBM_INSERT)
C(DBM_REPLACE)
{int(*p)(DBM*) = dbm_clearerr;}
{void(*p)(DBM*) = dbm_close;}
{int(*p)(DBM*,datum) = dbm_delete;}
{int(*p)(DBM*) = dbm_error;}
{datum(*p)(DBM*,datum) = dbm_fetch;}
{datum(*p)(DBM*) = dbm_firstkey;}
{datum(*p)(DBM*) = dbm_nextkey;}
{DBM*(*p)(const char*,int,mode_t) = dbm_open;}
{int(*p)(DBM*,datum,datum,int) = dbm_store;}
}
#else
static void f(){}
#endif
