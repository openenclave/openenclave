# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Detect C and C++ compiler options
# if not gcc, default to clang-7

COMPILER=$(notdir $(CC))
ifeq ($(COMPILER), gcc)
        USE_GCC = true
endif

ifeq ($(USE_GCC),)
        CC = clang-7
        COMPILER=clang
endif

CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs)

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../logs.edl --untrusted
	$(CC) -c $(CFLAGS) host.c
	$(CC) -c $(CFLAGS) logs_u.c
	$(CC) -o logshost logs_u.o host.o $(LDFLAGS)

clean:
	rm -f logshost host.o logs_u.o logs_u.c logs_u.h logs_args.h
