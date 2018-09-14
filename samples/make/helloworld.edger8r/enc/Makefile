# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

CC = clang-7

CFLAGS += -Wall -Werror -O2 -m64 -nostdinc -fPIC
CFLAGS += -mllvm -x86-speculative-load-hardening

INCLUDES += -I$(OE_INCLUDEDIR)
INCLUDES += -I$(OE_INCLUDEDIR)/libc

LDFLAGS += -Wl,--no-undefined 
LDFLAGS += -nostdlib 
LDFLAGS += -nodefaultlibs 
LDFLAGS += -nostartfiles 
LDFLAGS += -Wl,-Bstatic 
LDFLAGS += -Wl,-Bsymbolic 
LDFLAGS += -Wl,--export-dynamic 
LDFLAGS += -Wl,-pie

LIBRARIES += -L${OE_LIBDIR}/openenclave/enclave 
LIBRARIES += -loeenclave
LIBRARIES += -lmbedx509 
LIBRARIES += -lmbedcrypto 
LIBRARIES += -loelibc
LIBRARIES += -loecore

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	$(OE_BINDIR)/oeedger8r ../helloworld.edl --trusted
	$(CC) -c $(CFLAGS) $(INCLUDES) enc.c -o enc.o
	$(CC) -c $(CFLAGS) $(INCLUDES) helloworld_t.c -o helloworld_t.o
	$(CC) -o helloworldenc.so helloworld_t.o enc.o $(LDFLAGS) $(LIBRARIES)

sign:
	$(OE_BINDIR)/oesign helloworldenc.so helloworld.conf private.pem
clean:
	rm -f enc.o helloworldenc.so helloworldenc.signed.so private.pem public.pem helloworld_t.o helloworld_t.h helloworld_t.c helloworld_args.h

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
