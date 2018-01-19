#include <cpio.h>
#define C(n) switch(n){case n:;}
static void f(){
C(C_IRUSR)
C(C_IWUSR)
C(C_IXUSR)
C(C_IRGRP)
C(C_IWGRP)
C(C_IXGRP)
C(C_IROTH)
C(C_IWOTH)
C(C_IXOTH)
C(C_ISUID)
C(C_ISGID)
C(C_ISVTX)
C(C_ISDIR)
C(C_ISFIFO)
C(C_ISREG)
C(C_ISBLK)
C(C_ISCHR)
C(C_ISCTG)
C(C_ISLNK)
C(C_ISSOCK)
{char *s = "" MAGIC;}
}

