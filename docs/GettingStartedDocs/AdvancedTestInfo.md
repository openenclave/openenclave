Advanced test information
==========================

* If tests fail, `ctest -V` provides verbose information.
* Executing `ctest` from the build subfolder of a test executes only the contained test.

Only a small subset of libc/libcxx tests are enabled by default due to their huge
cost on building (a couple hours). Enable the full set by setting the corresponding cmake
`ENABLE_FULL_LIBC_TESTS` or `ENABLE_FULL_LIBCXX_TESTS` variables before building.
For example, run the following from your build subfolder:

```bash
cmake -DENABLE_FULL_LIBC_TESTS=ON -DENABLE_FULL_LIBCXX_TESTS=ON ..
make
```

Execute the tests via `ctest` (see `man ctest` for details).
