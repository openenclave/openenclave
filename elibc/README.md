elibc
=====

**elibc** is a minimal C library for **Linux** and **Windows**, suitable for
building building **mbed TLS** and **oeenlave**. It may also suffice for other
applications with minimal dependencies on the C library.

**Elibc** coexists with other C libraries by renaming all C library symbol
references through the use of inlines. For example, the **string.h** header
defines **strcpy** as follows.

```
char* elibc_strcpy(char* dest, const char* src);

ELIBC_INLINE
char* strcpy(char* dest, const char* src)
{
    return elibc_strcpy(dest, src);
}
```

Since **strcpy** is an inline function, the caller's object file contains a
reference to **oelibc_strcpy** rather than **strcpy**. This avoids conflicts
with other C libraries, but requires that the calling sources be recompiled
with the **elibc** headers.

**Elibc** implements functions from following headers. A quick inspection
of these headers will reveal the subset of functions supported.

- [**assert.h**](../include/openenclave/elibc/assert.h)
- [**ctype.h**](../include/openenclave/elibc/ctype.h)
- [**errno.h**](../include/openenclave/elibc/errno.h)
- [**limits.h**](../include/openenclave/elibc/limits.h)
- [**pthread.h**](../include/openenclave/elibc/pthread.h)
- [**sched.h**](../include/openenclave/elibc/sched.h)
- [**setjmp.h**](../include/openenclave/elibc/setjmp.h)
- [**stdarg.h**](../include/openenclave/elibc/stdarg.h)
- [**stddef.h**](../include/openenclave/elibc/stddef.h)
- [**stdint.h**](../include/openenclave/elibc/stdint.h)
- [**stdio.h**](../include/openenclave/elibc/stdio.h)
- [**stdlib.h**](../include/openenclave/elibc/stdlib.h)
- [**string.h**](../include/openenclave/elibc/string.h)
- [**time.h**](../include/openenclave/elibc/time.h)
- [**unistd.h**](../include/openenclave/elibc/unistd.h)

**Elibc** supports building of the **Open Enclave** core libraries, which
may be linked in the following order.

- **oeenclave**
- **mbedx509**
- **mbedcrypto**
- **oeelibc**
- **oecore**

Note that the **elibc** library (**oeelibc**) may be replaced with the **MUSL**
library (**oelibc**).
