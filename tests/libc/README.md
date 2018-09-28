libc2 tests
===========

This directory runs the MUSL libc unit tests. The **gentests.sh** script
reads **tests.supported** and generates a wrapper for each of these tests.

The unit tests are partitioned into three files:

* tests.all -- all unit tests.
* tests.supported -- unit tests that work.
* tests.broken -- unit tests that are broken.
* tests.unsupported -- unit tests that are unsupported.

After adding new tests to **tests.supported**, the test wrappers must be
regenerated as follows.

```
./gentest.sh
```

If this creates any new files, they must be added to the Git repository.
