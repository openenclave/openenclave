musl libc
================

This directory contains the musl libc library and the accompanying libc-test test
suite. The structure of the directory is as follows.

- musl/ (branch: `openenclave-musl-1.1.21`)

  The clone of musl libc mirror (hosted under the openenclave github organization) that
  is included as a git submodule, which points to a branch corresponding to a musl's release tag.
  To update the submodule, we use the following procedure:
  - Checkout the tag that we want to update to (assume the mirror has the corresponding branch)
    ```
    cd musl
    git checkout <openenclave-musl-1.x.x>
    ```
  - Check the diff between the tag and the previous tag and update the <openenclave-root>/libc/ correspondingly.
    ```
    git diff <old tag> <new tag> --stat
    ```
  - Ensure the OE SDK builds and tests run successfully.

- libc-test/ (commit: `b7ec467969a53756258778fa7d9b045f912d1c93`)

  The clone of libc-test that is included as a git submodule, which points to a recent
  commit. We usually update the submodule along with musl libc with following procedure:
  - Checkout the more recent commit
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
