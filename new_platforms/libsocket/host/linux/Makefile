# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# All objects we build and store in our shared library.
OBJECTS = socket_host.o socket_u.o

# Path to where OpenEnclave resides.
OE_PATH = ../../../..

# Path where the EDK files are.
OE_EDL_PATH = $(OE_PATH)/include/openenclave

# Path to where the OP-TEE Client API resides.
OPTEE_CLIENT = $(OE_PATH)/3rdparty/optee_client

DEFINES = -DOE_USE_OPTEE -D_DEBUG
INCLUDES =                                             \
    -I$(OE_PATH)/new_platforms/include/optee/host      \
    -I$(OE_PATH)/new_platforms/include/                \
    -I$(OE_PATH)/new_platforms/include/linux           \
    -I$(SGX_SDK)/include                               \
    -I$(OE_PATH)/include                               \
    -I$(OPTEE_CLIENT)/public

CFLAGS = $(DEFINES) $(INCLUDES) -g

# Additional defines and includes for code that is shared with the Windows
# implementation.
COMMON_DEFINES = -DLINUX
COMMON_INCLUDES = -I./

COMMON_CFLAGS = $(CFLAGS) $(COMMON_DEFINES) $(COMMON_INCLUDES)

# Toolchain selection.
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar

# Name of final output.
LIB_NAME = oesocket_host.a

oesocket_host.a: $(OBJECTS)
	@echo " [AR]\toesocket_host.a"
	@$(AR) rcs $(LIB_NAME) $(OBJECTS)

../socket_u.h ../socket_u.c: $(OE_EDL_PATH)/socket.edl
	@echo " [EDGE]\socket.edl"
	@$(OEEDGER8R) --untrusted --untrusted-dir .. --search-path "$(OE_PATH)/include" \
	                                                           "$(OE_EDL_PATH)/socket.edl"

socket_u.o: ../socket_u.c ../socket_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -include "sal_unsup.h" -c -o $@ $<

%.o: %.c ../socket_u.c ../socket_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	@rm -f $(LIB_NAME) $(OBJECTS)
	@echo "Done."
