# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Perform common configuration for building sample enclaves and hosts.

# Detect compiler.
ifneq ($(CC),cc)
        # CC explicitly specified.
else ifneq ($(shell $(CC) --version | grep clang),)
        # CC is default (cc), and aliases to clang.
else
        # CC is default (cc), and does not alias to clang.
        CLANG_VERSION = $(shell for v in "9" "8" "7"; do \
                                        if [ -n "$$(command -v clang-$$v)" ]; then \
                                                echo $$v; \
                                                break; \
                                        fi; \
                                done)

        ifneq ($(CLANG_VERSION),)
                CC = clang-$(CLANG_VERSION)
                CXX = clang++-$(CLANG_VERSION)
        endif
endif

# Choose the right pkg-config based on CC.
C_COMPILER = clang
CXX_COMPILER = clang++
ifeq ($(shell $(CC) --version | grep clang),)
        C_COMPILER = gcc
        CXX_COMPILER = g++
endif

# Define COMPILER for samples that use only C.
COMPILER = $(C_COMPILER)
