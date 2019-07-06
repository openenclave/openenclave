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
	oeedger8r ../attestation_plugin.edl --trusted
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 enc.c ./plugin1/plugin1.c ./plugin2/plugin2.c ./plugin3/plugin3.c
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 attestation_plugin_t.c -o attestation_plugin_t.o
	$(CC) -o attestation_plugin_enc attestation_plugin_t.o enc.o plugin1.o plugin2.o plugin3.o $(LDFLAGS)

sign:
	oesign sign -e attestation_plugin_enc -c attestation_plugin.conf -k private.pem

clean:
	rm -f enc.o attestation_plugin_enc attestation_plugin_enc.signed private.pem public.pem attestation_plugin_t.o attestation_plugin_t.h attestation_plugin_t.c attestation_plugin_args.h

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem