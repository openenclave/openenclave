# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OBJECTS = main.o SampleTA_u.o

EDL_PATH = ../../../../src
EDL_INC_PATH = ../../../../include
OE_EDL_PATH = $(OE_PATH)/openenclave

OE_PATH = ../../../../../include

DEFINES = -DOE_USE_OPTEE -D_DEBUG -DLINUX
INCLUDES =                                \
    -I../../../../include/optee/host      \
    -I../../../../include/                \
    -I../../../../include/linux           \
    -I$(SGX_SDK)/include                  \
    -I$(OE_PATH)

CFLAGS = $(DEFINES) $(INCLUDES) -g
CXFLAGS = $(CFLAGS) -std=c++11

LDFLAGS =                                              \
    -L../../../../src/Untrusted/linux                  \
    -L../../../../libsocket/host/linux                 \
    -L../../../../libstdio/host/linux                  \
    -L../../../../../3rdparty/optee_client/out/libteec \
    -l:oehost.a                                        \
    -l:oesocket_host.a                                 \
    -l:oestdio_host.a                                  \
    -l:libteec.a                                       \
    -lpthread

CC = $(CROSS_COMPILE)gcc
CX = $(CROSS_COMPILE)g++
AR = $(CROSS_COMPILE)ar

APP_NAME = sampleserverapp

$(APP_NAME): $(OBJECTS)
	@echo " [LD]\t$(APP_NAME)"
	@$(CX) -o $(APP_NAME) $(OBJECTS) $(LDFLAGS)

SampleTA_u.h SampleTA_u.c: $(OE_EDL_PATH)/stdio.edl  \
                           $(OE_EDL_PATH)/socket.edl \
                          ../../SampleTA.edl
	@echo " [EDGE]\SampleTA.edl"
	@$(OEEDGER8R) --untrusted --search-path "$(EDL_INC_PATH):$(OE_PATH)" \
	                                        "../../SampleTA.edl"

main.o: main.c SampleTA_u.h
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

SampleTA_u.o: SampleTA_u.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) -include sal_unsup.h -include stddef.h -c -o $@ $<

.PHONY: clean
clean:
	@rm -f $(APP_NAME) SampleTA_u.h SampleTA_u.c $(OBJECTS)
	@echo "Done."
