# Getting started with running static analysis tools

## scan-build

*Note: scan-build only works with clang and gcc and as such is only currently supported for linux builds*

1. Install scan-build-7 (or whatever version matches your version of clang)

    ```
    $ apt install clang-tools-7
    ```

2. (Optional) Create symlinks for scan-build and scan-view to avoid needing to specify a version. If you skip this step, just add the clang version to each `scan-*` command e.g. `scan-build-7 ...`

    ```{bash}
    $ ln -s /usr/bin/scan-build /usr/bin/scan-build-7
    $ ln -s /usr/bin/scan-view /usr/bin/scan-view-7
    ```

3. Run scan-build for cmake and make build commands

    For example:

    ```{bash}
    $ scan-build cmake .. -G Ninja
    $ scan-build ninja
    ```

    *Note: scan-build also works with the cmake GNU make generator*

4. View the output

    At the end of the scan-build output, it will print a command you can use to view the results.

    The output could look like:

    ```
    scan-build: 200 bugs found.
    scan-build: Run 'scan-view /tmp/scan-build-2019-12-12-102130-18694-1' to examine bug reports.
    ```

    Running `scan-view /tmp/scan-build-2019-12-12-102130-18694-1` will open results in a web browser.

## Interpreting warnings

Ideally, all warnings would be legitimate and CI/CD could reject PRs which introduce scan-build errors.
Unfortunately there are currently many scan-build errors in the OE codebase, and many of them are in
external code.

Specifically, errors reported from the 3rdparty directory should be ignored. Any other warnings are considered
bugs and should be fixed.

## Excluding directories

Clang 8 adds the ability to exclude specific directories from static analysis.

```{bash}
$ scan-build-8 cmake .. -G Ninja
$ scan-build-8 --exclude 3rdparty/ ninja
```

Additionally, scan-build can be run with a mismatched version of clang. For example,
scan-build-8 can use clang-7 as a compiler:

```
$ scan-build-8 --use-analyzer=/usr/bin/clang-7 cmake .. -G Ninja
$ scan-build-8 --use-analyzer=/usr/bin/clang-7 --exclude 3rdparty/ ninja
```
