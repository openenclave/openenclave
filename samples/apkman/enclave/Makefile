# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CRYPTO_LDFLAGS := $(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libs)

ifeq ($(LVI_MITIGATION), ControlFlow)
    ifeq ($(LVI_MITIGATION_BINDIR),)
        $(error LVI_MITIGATION_BINDIR is not set)
    endif
    # Only run once.
    ifeq (,$(findstring $(LVI_MITIGATION_BINDIR),$(CC)))
        CC := $(LVI_MITIGATION_BINDIR)/$(CC)
    endif
    COMPILER := $(COMPILER)-lvi-cfg
    CRYPTO_LDFLAGS := $(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libslvicfg)
endif

APKMAN_INITIALIZE=$(shell oeapkman)
APKMAN_ROOT=$(shell oeapkman root)
CFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(COMPILER) --variable=includedir)

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../sqlite.edl --trusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	oeapkman add sqlite-dev sqlite-static
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 -I$(APKMAN_ROOT)/usr/include enc.c -o enc.o
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 -I$(APKMAN_ROOT)/usr/include stubs.c -o stubs.o
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 sqlite_t.c -o sqlite_t.o
	$(CC) -o enclave sqlite_t.o enc.o stubs.o \
                 $(APKMAN_ROOT)/usr/lib/libsqlite3.a \
                 $(LDFLAGS) $(CRYPTO_LDFLAGS)

sign:
	oesign sign -e enclave -c sqlite.conf -k private.pem

clean:
	rm -f enc.o stubs.o enclave enclave.signed \
           private.pem public.pem sqlite_t.o sqlite_t.h sqlite_t.c sqlite_args.h

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
