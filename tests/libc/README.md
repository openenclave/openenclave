libc tests
==========

This directory runs the MUSL libc unit tests. It reads **tests.supported** and 
generates a wrapper (in the build directory) for each of these tests.

The unit tests are partitioned into three files:

* tests.all -- all unit tests.
* tests.supported -- unit tests that work.
* tests.broken -- unit tests that are broken.
* tests.unsupported -- unit tests that are unsupported.

Tests determined to be unsupportable should be moved from tests.broken to
tests.unsupportable.
