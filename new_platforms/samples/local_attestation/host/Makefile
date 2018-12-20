# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OBJECTS = host.o localattestation_u.o

EDL_PATH = ../../../src
EDL_INC_PATH = ../../../include
OE_EDL_PATH = $(OE_PATH)/openenclave

OE_PATH = ../../../../include

DEFINES = -DOE_USE_OPTEE -D_DEBUG -DLINUX
INCLUDES =                                \
    -I../../../include/optee/Untrusted \
    -I../../../include/                \
    -I../../../include/linux           \
    -I$(SGX_SDK)/include                  \
    -I$(OE_PATH)

CFLAGS = $(DEFINES) $(INCLUDES) -g
CXFLAGS = $(CFLAGS) -std=c++11

LDFLAGS =                                              \
    -L../../../src/Untrusted/linux                  \
    -L../../../libsocket/host/linux                 \
    -L../../../libstdio/host/linux                  \
    -L../../../../3rdparty/optee_client/out/libteec \
    -l:oehost.a                                        \
    -l:oesocket_host.a                                 \
    -l:oestdio_host.a                                  \
    -l:libteec.a                                       \
    -lpthread

CC = $(CROSS_COMPILE)gcc
CX = $(CROSS_COMPILE)g++
AR = $(CROSS_COMPILE)ar

APP_NAME = host

$(APP_NAME): $(OBJECTS)
	@echo " [LD]\t$(APP_NAME)"
	@$(CX) -o $(APP_NAME) $(OBJECTS) $(LDFLAGS)

localattestation_u.h localattestation_u.c: ../localattestation.edl
	@echo " [EDGE]\localattestation.edl"
	@$(OEEDGER8R) --untrusted --search-path "$(EDL_INC_PATH):$(OE_PATH)" \
	                                        "../localattestation.edl"

host.o: host.cpp localattestation_u.h
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

localattestation_u.o: localattestation_u.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) -include sal_unsup.h -include stddef.h -c -o $@ $<

.PHONY: clean
clean:
	@rm -f $(APP_NAME) localattestation_u.h localattestation_u.c $(OBJECTS)
	@echo "Done."
