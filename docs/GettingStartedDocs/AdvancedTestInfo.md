Advanced test information
==========================

If things fail, "**ctest -V**" provides verbose information. Executing ctest from a sub-dir executes the tests underneath.

Only a small subset of libc/libcxx tests are enabled by default due to their huge
cost on building (a couple hours). Enable the full set by setting the corresponding cmake variable
**ENABLE_FULL_LIBC_TESTS/ENABLE_FULL_LIBCXX_TESTS** before building.

```
build$ cmake -DENABLE_FULL_LIBC_TESTS=ON -DENABLE_FULL_LIBCXX_TESTS=ON ..
build$ make
```

To run valgrind-tests, add "**-D ExperimentalMemCheck**" to the ctest call. 
Enclave tests all seem to fail today, though this succeeds:

```
build$ ctest -D ExperimentalMemCheck -R oeelf
```
Execute the tests via ctest (see "man ctest" for details).
