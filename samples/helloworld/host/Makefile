# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Detect C and C++ compiler options
# if not gcc, default to clang-8

COMPILER=$(notdir $(CC))
ifeq ($(COMPILER), gcc)
        USE_GCC = true
endif

ifeq ($(USE_GCC),)
        CC = clang-8
        COMPILER=clang
endif

CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs)

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../helloworld.edl --untrusted
	$(CC) -g -c $(CFLAGS) host.c
	$(CC) -g -c $(CFLAGS) helloworld_u.c
	$(CC) -o helloworldhost helloworld_u.o host.o $(LDFLAGS)

clean:
	rm -f helloworldhost host.o helloworld_u.o helloworld_u.c helloworld_u.h helloworld_args.h
