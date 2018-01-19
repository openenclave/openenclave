#include <dirent.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(DIR)
T(struct dirent)
#ifdef _XOPEN_SOURCE
T(ino_t)
#endif
{
struct dirent x;
#ifdef _XOPEN_SOURCE
F(ino_t,  d_ino)
#endif
F(char,   d_name[0])
}
{int(*p)(const struct dirent**,const struct dirent**) = alphasort;}
{int(*p)(DIR*) = closedir;}
{int(*p)(DIR*) = dirfd;}
{DIR*(*p)(int) = fdopendir;}
{DIR*(*p)(const char*) = opendir;}
{struct dirent*(*p)(DIR*) = readdir;}
{int(*p)(DIR*restrict,struct dirent*restrict,struct dirent**restrict) = readdir_r;}
{void(*p)(DIR*) = rewinddir;}
{int(*p)(const char*,struct dirent***,int(*)(const struct dirent*),int(*)(const struct dirent**,const struct dirent**)) = scandir;}
#ifdef _XOPEN_SOURCE
{void(*p)(DIR*,long) = seekdir;}
{long(*p)(DIR*) = telldir;}
#endif
}
