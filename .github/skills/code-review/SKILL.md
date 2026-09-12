---
name: code-review
description: Review code changes in the Open Enclave SDK repository against its coding conventions, style guide, security expectations and PR guidelines. Use when reviewing a pull request, a diff, or newly written C/C++/CMake code in this repository.
---

# Open Enclave code review

Review changes for correctness, security and consistency with the conventions
documented in [docs/Community/DevelopmentGuide.md](../../../docs/Community/DevelopmentGuide.md),
[docs/Community/Contributing.md](../../../docs/Community/Contributing.md) and
[docs/ApiGuidelines.md](../../../docs/ApiGuidelines.md).

Report only high-confidence issues. Do not comment on formatting that
`clang-format` / `cmake-format` already enforce; instead point the author at the
formatting scripts.

## How to review

1. Get the change set: `git diff` (unstaged), `git diff --staged`, or
   `git diff <base>...HEAD` for a branch.
2. Read the surrounding code for each hunk. The existing style of a file always
   takes precedence over the general guidelines.
3. Group findings by severity: correctness/security bugs first, then API and
   convention issues, then optional suggestions.

## Correctness and security

Open Enclave code frequently runs inside an enclave and processes untrusted
input, so pay particular attention to:

- Host-supplied or untrusted buffers: enclave code must validate pointers with
  `oe_is_outside_enclave` / `oe_is_within_enclave` before use, and must copy
  data into enclave memory before validating it (avoid TOCTOU on host memory).
- Integer overflow in size/length arithmetic before allocation or copying.
- Use of the safe helpers (`oe_memcpy_s`, `oe_secure_zero_fill`,
  `oe_secure_memcpy`, ...) rather than raw `memcpy`/`memset` for secrets.
- Error handling: every failure path should propagate an `oe_result_t` via
  `OE_CHECK` / `OE_RAISE`, initialize `result` to `OE_UNEXPECTED`, and clean up
  in the `done:` label. Check that allocations and crypto contexts are released
  on every path.
- Secrets (keys, report data) zeroed before being freed or going out of scope.
- No new use of unbounded string functions (`strcpy`, `sprintf`, `strcat`).
- Changes to public headers under `include/openenclave/` are ABI/API surface:
  flag breaking changes, missing doxygen with `[in]`/`[out]` annotations, and
  missing `CHANGELOG.md` entries.

## Conventions

- Fixed-width types (`uint64_t`, `int32_t`), not `long` / `unsigned char`.
- `lower_snake_case` for variables, fields and functions;
  `UPPER_SNAKE_CASE` for macros and constants.
- `oe_` prefix for global-namespace Open Enclave names; leading `_` for
  file-scope statics and for `struct` tags, with a matching `_t` typedef.
- Full words rather than abbreviations (`widget_count`, not `num_widgets`;
  `memory_context`, not `mem_ctx`).
- `const`, `static` and visibility modifiers used to minimize exposure; avoid
  global variables.
- License header at the top of every new file:
  `// Copyright (c) Open Enclave SDK contributors.` /
  `// Licensed under the MIT License.` (with the file's comment marker).

## Tests and documentation

- New features should come with tests under `tests/`; bug fixes should add a
  test that fails without the fix.
- Behavior changes should update the relevant `README.md` / `docs/` pages, and
  new features, deprecations and breaking changes belong in `CHANGELOG.md`.

## PR hygiene

- The PR should be focused: no unrelated changes, no pure style churn, no edits
  to licensing files or headers.
- Commits should build and pass tests on their own.

## Local checks to suggest

```sh
./scripts/format-code     # clang-format / cmake-format
./scripts/check-license   # license headers
```
