scripts
=======

This directory contains the following scripts.

- [check-ci][] - Checks that requirements for license headers, code formatting,
  and code linting have been met before changes should be merged
- [check-license][] - Prints a list of sources missing the license header
- [check-linters][] - Runs ShellCheck across scripts to lint them
- [deploy-docs][] - Deploys HTML documentation to GitHub pages
- [format-code][] - Formats Open Enclave C/C++ code using `clang-format`
- [install-open-enclave-stack][] - This is pending deprecation
- [install-prereqs][] - Installs packages needed to build Open Enclave
- [pre-commit][] - A [Git pre-commit hook](https://git-scm.com/docs/githooks)
  for developers
- [test-build-config][] - This will be deprecated by writing the configuration
  into the `Jenkinsfile`
