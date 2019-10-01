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
	oeedger8r ../switchless.edl --untrusted
	$(CC) -g -c $(CFLAGS) host.c
	$(CC) -g -c $(CFLAGS) switchless_u.c
	$(CC) -o switchlesshost switchless_u.o host.o $(LDFLAGS)

clean:
	rm -f switchlesshost host.o switchless_u.o switchless_u.c switchless_u.h switchless_args.h
