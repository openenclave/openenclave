# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include $(OPENENCLAVE_CONFIG)

all: build

CXXFLAGS=-Wall -O2

INCLUDES = -I$(OE_INCLUDEDIR)

LDFLAGS += -rdynamic

LIBRARIES += -L$(OE_LIBDIR)/openenclave/host
LIBRARIES += -loehost
LIBRARIES += -lcrypto
LIBRARIES += -lpthread
LIBRARIES += -ldl
LIBRARIES += -lsgx_enclave_common
LIBRARIES += -lsgxoeql
LIBRARIES += -lsgx_urts_ng

build:
	g++ -c $(CXXFLAGS) $(INCLUDES) host.cpp
	g++ -o sorthost host.o $(LDFLAGS) $(LIBRARIES)

clean:
	rm -f sorthost host.o

