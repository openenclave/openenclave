musl libc
================

This directory contains the musl libc library and the accompanying libc-test test
suite. The structure of the directory is as follows.

- musl/ (tag: `v1.1.21`)

  The clone of musl libc that is included as a git submodule, which points to
  a recent release tag. To update the submodule, we use the following procedure:
  - Checkout the tag that we want to update to.
    ```
    cd musl
    git checkout <new tag>
    ```
  - Check the diff between the tag and the previous tag and update the <openenclave-root>/libc/ correspondingly.
    ```
    git diff <old tag> <new tag> --stat
    ```
  - Ensure the OE SDK builds and tests run successfully.

- libc-test/ (commit: `a51df71b050f3f9dfdc0a7d90978b57277b582ec`)

  The clone of libc-test that is included as a git submodule, which points to a recent
  commit. We usually update the submodule along with musl libc with following procedure:
  - Checkout the more recent commit (the date that matches the version of musl libc)
    ```
    cd libc-test
    git fetch
    git checkout <commit>
    ```
  - Check the code diff and update the <openenclave-root>/tests/libc correspondingly.
  - Ensure the OE SDK builds and tests run successfully.
  Refer to https://repo.or.cz/libc-test.git for the commit history.

- patches/
  The list of OE-specific patches that we apply to the musl libc.

- CMakeLists.txt
  The cmake script for installing the musl libc headers.

- append-deprecations
  The script to append the `#include <bits/deprecations.h>` to musl libc headers. The patched
  headers will be installed as part of OE release packages.
