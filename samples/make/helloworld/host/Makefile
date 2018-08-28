# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

all: build

CFLAGS=-Wall -g

INCLUDES = -I$(OE_INCLUDEDIR)

LDFLAGS += -rdynamic

LIBRARIES += -L$(OE_LIBDIR)/openenclave/host
LIBRARIES += -loehost
LIBRARIES += -lcrypto
LIBRARIES += -lpthread
LIBRARIES += -ldl


LIBRARIES += -lsgx_enclave_common
LIBRARIES += -lsgx_ngsa_ql
LIBRARIES += -lsgx_urts_ng

build:
	gcc -c $(CFLAGS) $(INCLUDES) host.c
	gcc -o helloworldhost host.o $(LDFLAGS) $(LIBRARIES)

clean:
	rm -f helloworldhost host.o

