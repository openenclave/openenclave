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

CFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --libs)

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../logs.edl --trusted
	$(CC) -c $(CFLAGS) enc.c -o enc.o
	$(CC) -c $(CFLAGS) logs_t.c -o logs_t.o
	$(CC) -o logsenc.so logs_t.o enc.o $(LDFLAGS)

sign:
	oesign logsenc.so logs.conf private.pem

clean:
	rm -f enc.o logsenc.so logsenc.signed.so private.pem public.pem logs_t.o logs_t.h logs_t.c logs_args.h

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
