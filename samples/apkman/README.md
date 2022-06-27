# oeapkman Sample

This sample demonstrates installing and using the [sqlite](https://sqlite.org/index.html)
database static library via `oeapkman`. `sqlite` is used to create, populate,
and query an in-memory database within an enclave.

# oeapkman Overview

`oeapkman` is a tool for installing and using [Alpine Linux](https://www.alpinelinux.org/)
static libraries in enclaves. Currently, `oeapkman` is Linux only.

## Why Alpine Linux?

OE SDK uses [MUSL](https://musl.libc.org/) as its enclave C library.
Most Linux distributions use GLIBC as the native C library.
Due to incompatibilities between MUSL and GLIBC, the static libraries available
in most Linux distrubtions cannot be used within enclaves.
MUSL is currently not 100% binary compatible with GLIBC as explained here:
- https://www.musl-libc.org/faq.html
- https://wiki.musl-libc.org/functional-differences-from-glibc.html

Libraries that successfully compile with GLIBC may not always
compile with MUSL. There are also runtime behavior differences.

Unlike other Linux distributions, Alpine Linux uses MUSL as its native C library.
All static libraries available in Alpine Linux have been patched and ensured to
work with MUSL. Therefore these static libraries are compatible for use with OE SDK
which also uses MUSL as the enclave C library.

*Note that OE SDK does not implement all the system calls needed by MUSL;
nor does it include all the libc functions available in MUSL. Therefore, the
enclave author might need to implement the functionality that is currently missing
in OE's libc to enable all the features of a static library.*

### oeapkman commands

`oeapkman` is a wrapper over Alpine Linux's package manager `apk`.
It's command syntax closely mirrors that of `apk`.

Commands have the following syntax: `oeapkman command parameters`

The command `oeapkman help` prints a message describing all the commands and their usage.

#### Installing packages

The command `oeapkman add package` installs the given package.

For example, the `sqlite` static library can be installed thus:

```bash
$ oeapkman add sqlite-static
(1/1) Installing sqlite-static (3.35.5-r0)
OK: 414 MiB in 47 packages
```

Multiple packages can be specified to install them all at once.
```bash
$ oeapkman add sqlite-static zlib-static
(1/2) Installing sqlite-static (3.35.5-r0)
(2/2) Installing zlib-static (1.2.11-r3)
OK: 414 MiB in 48 packages
```


To develop enclaves using a static library, the headers files for the library also need
to be installed. The header files for static libraries are often found in the corresponding
`-dev` package. The header files needed for using `sqlite` are available in the `sqlite-dev`
package.

```bash
$ oeapkman add sqlite-dev
(1/2) Installing sqlite-libs (3.35.5-r0)
(2/2) Installing sqlite-dev (3.35.5-r0)
OK: 414 MiB in 48 packages
```

### Searching for packages

If you are unsure of the exact package name, but know what it is (e.g., sqlite),
you can find the exact package name at the
[Search Packages By Name](https://pkgs.alpinelinux.org/packages) site.

For example, by specifying "sqlite*" in the name field, and choosing branch v3.14 and
arch x86_64, the list of sqlite packages is found thus:
https://pkgs.alpinelinux.org/packages?name=sqlite*&branch=v3.14&arch=x86_64

Typically packages named `-static` contain static libraries and therefore `sqlite-static`
is the package that must be installed.

The license for each package is also listed in the search results.

On the other hand, if you know the contents of a package, but don't know its name, you
can find the exact package name by searching by contents at the
[Search Packages By Contents](https://pkgs.alpinelinux.org/contents) site.

For example, searching for the header file `sqlite3.h` via
https://pkgs.alpinelinux.org/contents?file=sqlite3.h&path=&name=&branch=edge&arch=x86_64
reveals that `sqlite-dev` is the package that must be installed for obtaining
`sqlite` headers.

The relative path of the file is also listed. This is helpful for specifying the path
of the header file to the compiler. See the [apkman root](#oeapkman-root) section below.

Similarly, searching for `libsqlite*.a` via
https://pkgs.alpinelinux.org/contents?file=libsqlite*.a&path=&name=&branch=edge&arch=x86_64
reveals that the package of interest is `sqlite-static` and that the library `libsqlite3.a`
exists in `/usr/lib`. This relative path is useful for helping the linker locate the library
as described in the next section.

### oeapkman root

Under the hood, `oeapkman` maintains an Alpine Linux distribution whose root filesystem resides
at the location given by the command `oeapkman root`:

```bash
$ oeapkman root
/home/username/.oeapkman/alpine-fs-3.14.1-x86_64
```

The static libraries and header files installed via `oeapkman` are installed at their usual
locations within the Alpine Linux root filesystem. Header files are typically found in
'/usr/include' whereas static libraries are found in '/usr/lib'.

```bash
$ ls $(oeapkman root)/usr/include
sqlite3ext.h  sqlite3.h

$ ls $(oeapkman root)/usr/lib
...
libsqlite3.a
...
```


#### Using header files and static libraries

Once the library and the header files are installed, they can be used in enclave code.

```c
// enclave_source.c
#include <sqlite3.h>
...
```

To successfully compile the above code, however, the path to the header file must be
specified to the C/C++ compiler. The path to the header file can be specified relative
to `apkman root` described above.

```bash
clang -c enclave_source.c --nostdinc -I $(apkman root)/usr/include
```

Similarly, the path to the static library must be specified to the linker.
```bash
clang -o enclave enclave_source.o -L $(apkman root)/usr/lib libsqlite3.a ...
```

#### oeapkman cmake usage

`oeapkman` is available as an exported cmake target. It can therefore be invoked thus:

```cmake
# CMakeLists.txt
...
add_custom_target(
    sqlite-libs
    COMMAND oeapkman add sqlite-dev sqlite-static
)
```

In order to fetch the root folder, `oeapkman` is executed twice.
The first time to initialize it and ignore output. The second time to fetch the root.
Since `add_custom_target` and `add_custom_command` don't allow capturing program
output, `execute_process` is used instead to capture the output of `oeapkman root`.

```cmake
# CMakeLists.txt

# Fetch the root folder
get_target_property(OEAPKMAN openenclave::oeapkman LOCATION)

# Execute once so that it is initialized. Any output produced is ignored.
execute_process(COMMAND "${OEAPKMAN}")

# Execute again to fetch the root folder into the variable APKMAN_ROOT.
execute_process(COMMAND "${OEAPKMAN}" root
 OUTPUT_VARIABLE APKMAN_ROOT
 OUTPUT_STRIP_TRAILING_WHITESPACE)

# Add include paths using APKMAN_ROOT.
target_include_directories(
  enclave
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
          # Add include path relative to ROOT folder.
          ${APKMAN_ROOT}/usr/include)

# Add libraries using APKMAN_ROOT.
target_link_libraries(
  enclave openenclave::oeenclave
  # Add static library to linker using root folder.
  "-L  ${APKMAN_ROOT}/usr/lib" libsqlite3.a
  openenclave::oecrypto${OE_CRYPTO_LIB} openenclave::oelibc)
```

# Sample Overview

The sample enclave uses `sqlite` to create an in-memory database.

See [enclave/main.c](enclave/main.c)

```c
...
#include <sqlite3.h>
...
int enc_main(int argc, const char** argv)
{
    sqlite3* db = NULL;
    const char* sql = NULL;
    sqlite3_stmt* stmt = NULL;

   ...

    // Open database
    SQL_TEST(sqlite3_open(":memory:", &db));
```

It then creates a table within the database and adds a few rows.
```c
...
    /* Create table */
    sql = "CREATE TABLE PATIENT("
          "ID INT PRIMARY KEY     NOT NULL,"
          "NAME           TEXT    NOT NULL,"
          "AGE            INT     NOT NULL,"
          "ADDRESS        TEXT    NOT NULL);";

    /* Execute SQL statement */
    SQL_TEST(sqlite3_exec(db, sql, callback, 0, NULL));

    /* Insert items */
    sql = "INSERT INTO PATIENT (ID,NAME,AGE,ADDRESS) "
          "VALUES (1, 'Dennis', 72, 'California'); "
          "INSERT INTO PATIENT (ID,NAME,AGE,ADDRESS) "
          "VALUES (2, 'Bjarne', 65, 'Texas'); ";
    SQL_TEST(sqlite3_exec(db, sql, callback, 0, NULL));
```

It then performs a SELECT operation before closing the database.
```c
   /* Fetch items */
    sql = "SELECT * from PATIENT";
    SQL_TEST(sqlite3_exec(db, sql, callback, NULL, NULL));

    SQL_TEST(sqlite3_finalize(stmt));
    SQL_TEST(sqlite3_close(db));
```

As described earlier, `sqlite` library is installed using the `oeapkman` command
and the header files and static library paths are specified relative to the `root` folder.

[enclave/CMakeLists.txt](enclave/CMakeLists.txt)
```cmake

# For sqlite headers.
target_include_directories(
  enclave
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
          # sqlite include path.
          ${APKMAN_ROOT}/usr/include)

target_link_libraries(
  enclave openenclave::oeenclave "-L  ${APKMAN_ROOT}/usr/lib" libsqlite3.a
  openenclave::oecrypto${OE_CRYPTO_LIB} openenclave::oelibc)
```

Similarly, in the Makefile based workflow, the `oeapkman add sqlite-static sqlite-dev` and
`oeapkman root` commands are used to enable use of the `sqlite` static library.

See [enclave/Makefile](enclave/Makefile)

## stubs

`sqlite` uses some functions that are not currently implemented by OE SDK.
- dlopen, dlclose, dlsym, dlerror
- fchmod, fchown
- mremap
- posix_fallocate
- readlink
- utimes

Since in-memory databases work without implementing these functions, these
functions have been provided only as stubs.

In general, the enclave author must test their enclaves well enough to determine
whether a specific missing libc function ought to be implemented or stubbed out.

## output
When run, the sample is expected to produce output similar to the following:
```bash
$ make run
host/sqlite_host ./enclave/enclave.signed
sqlite version: 3.35.5
sqlite3_open(":memory:", &db) succeeded
sqlite3_exec(db, sql, callback, 0, NULL) succeeded
sqlite3_exec(db, sql, callback, 0, NULL) succeeded
ID = 1
NAME = Dennis
AGE = 72
ADDRESS = California

ID = 2
NAME = Bjarne
AGE = 65
ADDRESS = Texas

sqlite3_exec(db, sql, callback, NULL, NULL) succeeded
sqlite3_finalize(stmt) succeeded
sqlite3_close(db) succeeded

```
