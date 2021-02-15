scripts
=======

This directory contains the following scripts.

- [check-ci][] - Checks that requirements for license headers, code formatting,
  and code linting have been met before changes should be merged
- [check-license][] - Prints a list of sources missing the license header
- [check-linters][] - Runs ShellCheck across scripts to lint them
- [commit-msg][] - A [Git pre-commit hook](https://git-scm.com/docs/githooks)
  to ensure that commit messages contain a [DCO](https://developercertificate.org)
  sign-off
- [deploy-docs][] - Deploys HTML documentation to GitHub pages
- [format-code][] - Formats Open Enclave C/C++ code using `clang-format`
- [pre-commit][] - A [Git pre-commit hook](https://git-scm.com/docs/githooks)
  for developers
