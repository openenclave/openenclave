# All objects we build and store in our shared library.
OBJECTS = TcpsCalls_u.o teehost-optee.o urpc-optee.o ufiles.o \
          uTcpsFileOcalls.o usockets.o buffer.o uhelper-shared.o \
          uhelper.o oeshim_u.o uProtectedFs-optee.o oeresult.o \
          oeshim-common.o stdext.o uTcpsFileOcalls-shared.o socket_u.o

# Path to where OpenEnclave resides.
OE_PATH = ../../../..

# Path where the TCPS SDK's EDK files are.
EDL_PATH = ../..
EDL_INC_PATH = ../../../Inc
OE_EDL_PATH = $(OE_PATH)/include/openenclave

# Path to where the OP-TEE Client API resides.
OPTEE_CLIENT = ../../../../3rdparty/optee_client

DEFINES = -DUNTRUSTED_CODE -DUSE_OPTEE -D_DEBUG
INCLUDES =                         \
    -I../../../Inc/optee/Untrusted \
    -I../../../Inc/                \
    -I../../../Inc/linux           \
    -I../../                       \
    -I../                          \
    -I$(SGX_SDK)/include           \
    -I$(OE_PATH)/include           \
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
LIB_NAME = oehost.a

oehost.a: $(OBJECTS)
	@echo " [AR]\toehost.a"
	@$(AR) rcs $(LIB_NAME) $(OBJECTS)

../TcpsCalls_u.h ../TcpsCalls_u.c: $(EDL_PATH)/TcpsCalls.edl \
								   $(EDL_PATH)/TcpsFile.edl
	@echo " [EDGE]\TcpsCalls.edl"
	@sgx_edger8r --untrusted --untrusted-dir .. --search-path "$(EDL_PATH):$(EDL_INC_PATH):$(SGX_SDK)/include" \
	                                                          "$(EDL_PATH)/TcpsCalls.edl"

../socket_u.h ../socket_u.c: $(OE_EDL_PATH)/socket.edl
	@echo " [EDGE]\socket.edl"
	@$(OEEDGER8R) --untrusted --untrusted-dir .. --search-path "$(OE_PATH)/include" \
	                                                           "$(OE_EDL_PATH)/socket.edl"

buffer.o: ../../buffer.c ../TcpsCalls_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -std=c99 -c -o $@ $<

uhelper-shared.o: ../uhelper-shared.c ../TcpsCalls_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

oeshim-common.o: ../../oeshim-common.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

oeshim_u.o: ../oeshim_u.c ../TcpsCalls_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

oeresult.o: ../../oeresult.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

uProtectedFs-optee.o: ../uProtectedFs-optee.c ../TcpsCalls_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

uTcpsFileOcalls-shared.o: ../uTcpsFileOcalls-shared.c ../TcpsCalls_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

TcpsCalls_u.o: ../TcpsCalls_u.c ../TcpsCalls_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

socket_u.o: ../socket_u.c ../socket_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -include "sal_unsup.h" -c -o $@ $<

%.o: %.c ../TcpsCalls_u.h ../TcpsCalls_u.c ../socket_u.c ../socket_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	@rm -f $(LIB_NAME) TcpsCalls_u.h TcpsCalls_u.c $(OBJECTS)
	@echo "Done."
