# All objects we build and store in our shared library.
OBJECTS = oeoverintelsgx_u.o teehost_optee.o urpc_optee.o \
          buffer.o uhelper_shared.o uhelper.o oeshim_host.o oeresult.o \
          optee_common.o stdext.o

# Path to where OpenEnclave resides.
OE_PATH = ../../../..

# Path where the TCPS SDK's EDK files are.
EDL_PATH = ../..
EDL_INC_PATH = ../../../Inc
OE_EDL_PATH = $(OE_PATH)/include/openenclave

# Path to where the OP-TEE Client API resides.
OPTEE_CLIENT = ../../../../3rdparty/optee_client

DEFINES = -DOE_USE_OPTEE -D_DEBUG
INCLUDES =                             \
    -I../../../include/optee/host      \
    -I../../../include/optee           \
    -I../../../include/                \
    -I../../../include/linux           \
    -I../../                           \
    -I../                              \
    -I$(SGX_SDK)/include               \
    -I$(OE_PATH)/include               \
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

../oeoverintelsgx_u.h ../oeoverintelsgx_u.c: $(EDL_PATH)/oeoverintelsgx.edl
	@echo " [EDGE]\oeoverintelsgx.edl"
	@sgx_edger8r --untrusted --untrusted-dir .. --search-path "$(EDL_PATH):$(EDL_INC_PATH):$(SGX_SDK)/include" \
	                                                          "$(EDL_PATH)/oeoverintelsgx.edl"

../stdio_u.h ../stdio_u.c: $(OE_EDL_PATH)/stdio.edl
	@echo " [EDGE]\stdio.edl"
	@$(OEEDGER8R) --untrusted --untrusted-dir .. --search-path "$(EDL_PATH):$(EDL_INC_PATH):$(SGX_SDK)/include" \
	                                                           "$(OE_EDL_PATH)/stdio.edl"

buffer.o: ../../buffer.c ../oeoverintelsgx_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -std=c99 -c -o $@ $<

uhelper_shared.o: ../uhelper_shared.c ../oeoverintelsgx_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

optee_common.o: ../../optee_common.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

oeshim_host.o: ../oeshim_host.c ../oeoverintelsgx_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

oeresult.o: ../../oeresult.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

oeoverintelsgx_u.o: ../oeoverintelsgx_u.c ../oeoverintelsgx_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

%.o: %.c ../oeoverintelsgx_u.h ../oeoverintelsgx_u.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	@rm -f $(LIB_NAME) oeoverintelsgx_u.h oeoverintelsgx_u.c $(OBJECTS)
	@echo "Done."
