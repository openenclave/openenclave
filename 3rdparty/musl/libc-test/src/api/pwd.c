#include <pwd.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
static void f()
{
T(gid_t)
T(uid_t)
T(size_t)
{
struct passwd x;
F(char*,pw_name)
F(uid_t,pw_uid)
F(gid_t,pw_gid)
F(char*,pw_dir)
F(char*,pw_shell)
}
{struct passwd*(*p)(const char*) = getpwnam;}
{int(*p)(const char*,struct passwd*,char*,size_t,struct passwd**) = getpwnam_r;}
{struct passwd*(*p)(uid_t) = getpwuid;}
{int(*p)(uid_t,struct passwd*,char*,size_t,struct passwd**) = getpwuid_r;}
#ifdef _XOPEN_SOURCE
{void(*p)(void) = endpwent;}
{struct passwd*(*p)(void) = getpwent;}
{void(*p)(void) = setpwent;}
#endif
}
