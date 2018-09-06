# Advanced build information

In addition to the standard CMake variables, the following CMake variables
control the behavior of the Linux make generator for Open Enclave:

| Variable                 | Description                                          |
|--------------------------|------------------------------------------------------|
| CMAKE_BUILD_TYPE         | Build configuration (*Debug*, *Release*, *RelWithDebInfo*). Default is *Debug*. |
| ENABLE_FULL_LIBC_TESTS   | Enable full Libc tests. Default is disabled, enable with setting to "On", "1", ... |
| ENABLE_FULL_LIBCXX_TESTS | Enable full Libc++ tests. Default is disabled, enable with setting to "On", "1", ... |
| ENABLE_REFMAN            | Enable building of reference manual. Requires Doxygen to be installed. Default is enabled, disable with setting to "Off", "No", "0", ... |


E.g., to generate an optimized release-build with debug info, use

```
 build$ cmake .. -DCMAKE_BUILD_TYPE=relwithdebinfo
```

The following build types cause the **C** **NDEBUG** macro to be defined.

- **CMAKE_BUILD_TYPE="Release"**
- **CMAKE_BUILD_TYPE="RelWithDebInfo"**

Whereas **CMAKE_BUILD_TYPE="Debug"** causes it to be undefined. Defining the 
**NDEBUG** macro affects the behavior of **Open Enclave** in three ways.

- The **oe_assert()** and **assert()** macros become no-ops.
- The **oe_backtrace()** function returns an empty backtrace.
- The debug allocator is disabled. The debug allocator checks for memory errors
  during enclave termination.

Multiple variables can be defined at the call with multiple "-D*Var*=*Value*" arguments.

Once cmake has run and the build is configured, build with

```
build$ make
```

This builds the entire Open Enclave SDK, creating the following files.

| Filename                          | Description                                           |
|-----------------------------------|-------------------------------------------------------|
| output/bin/oegen                  | Utility for generating ECALL and OCALL stubs from IDL |
| output/bin/oesign                 | Utility for signing enclaves                          |
| output/lib/enclave/liboecore.a    | Core library for building enclave applications (defines enclave intrinsics) |
| output/lib/enclave/liboeenclave.a | Enclave library for building enclave applications (defines enclave features) |
| output/lib/enclave/liboelibc.a    | C runtime library for enclave                         |
| output/lib/enclave/liboelibcxx.a  | C++ runtime library for enclave                       |
| output/lib/host/liboehost.a       | Library for building host applications                |
| output/share/doc/openenclave/     | HTML API reference for Open Enclave                    |

If things break, set the **VERBOSE** make variable to print all invoked commands.

```
build$ make VERBOSE=1
```

Building from within a subtree of the build-tree builds all dependencies for that directory as well.
"**make clean**" is handy before a spot-rebuild in verbose mode.

A successful build only outputs the HTML API reference into the build-tree.
To update the doxygen generated documentation available at https://microsoft.github.io/openenclave,
please follow instructions [here](../refman/doxygen-howto.md)
