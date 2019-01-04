# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OBJECTS_RIOT = RiotAes128.o RiotBase64.o RiotCrypt.o RiotDerEnc.o \
               RiotEcc.o RiotHmac.o RiotKdf.o RiotSha256.o TcpsId.o

OBJECTS_TINYCBOR = cborencoder.o cborparser.o cborhelper.o

OBJECTS_MBEDTLS = x509_crt.o x509.o md.o asn1parse.o md_wrap.o \
          certs.o pem.o sha512.o ripemd160.o pkparse.o md5.o des.o \
		  base64.o pk.o rsa.o bignum.o sha256.o pk_wrap.o ecp.o \
		  ecp_curves.o ecdsa.o rsa_internal.o asn1write.o sha1.o \
		  pkcs5.o hmac_drbg.o pkcs12.o oid.o arc4.o cipher.o aes.o \
		  ccm.o gcm.o cipher_wrap.o camellia.o blowfish.o

# All objects we build and store in our shared library.
OBJECTS = oeinternal_u.o teehost_optee.o urpc_optee.o uhelper_shared.o \
          uhelper.o oeshim_host.o optee_common.o stdext.o \
		  $(OBJECTS_RIOT) $(OBJECTS_TINYCBOR) $(OBJECTS_MBEDTLS)

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
    -I./                               \
    -I../                              \
    -I../../                           \
    -I../../../include/optee/host      \
    -I../../../include/optee           \
    -I../../../include/                \
    -I../../../include/linux           \
    -I$(SGX_SDK)/include               \
    -I$(OE_PATH)/3rdparty/mbedtls/mbedtls/include \
    -I$(OE_PATH)/3rdparty/RIoT/CyReP/cyrep \
    -I$(OE_PATH)/3rdparty/RIoT/CyReP/tcps \
    -I$(OE_PATH)/3rdparty/RIoT/External/tinycbor/src \
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

../oeinternal_u.h ../oeinternal_u.c: $(EDL_PATH)/oeinternal.edl
	@echo " [EDGE]\oeinternal.edl"
	@$(OEEDGER8R) --untrusted --untrusted-dir .. --search-path "$(EDL_PATH):$(EDL_INC_PATH):$(SGX_SDK)/include" \
	                                                           "$(EDL_PATH)/oeinternal.edl"

../stdio_u.h ../stdio_u.c: $(OE_EDL_PATH)/stdio.edl
	@echo " [EDGE]\stdio.edl"
	@$(OEEDGER8R) --untrusted --untrusted-dir .. --search-path "$(EDL_PATH):$(EDL_INC_PATH):$(SGX_SDK)/include" \
	                                                           "$(OE_EDL_PATH)/stdio.edl"

uhelper_shared.o: ../uhelper_shared.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

optee_common.o: ../../optee_common.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

oeshim_host.o: ../oeshim_host.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

oeinternal_u.o: ../oeinternal_u.c ../oeinternal_u.h
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

# RIoT

RiotAes128.o: $(OE_PATH)/3rdparty/RIoT/CyReP/RiotAes128.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

RiotBase64.o: $(OE_PATH)/3rdparty/RIoT/CyReP/RiotBase64.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

RiotCrypt.o: $(OE_PATH)/3rdparty/RIoT/CyReP/RiotCrypt.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

RiotDerEnc.o: $(OE_PATH)/3rdparty/RIoT/CyReP/RiotDerEnc.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

RiotEcc.o: $(OE_PATH)/3rdparty/RIoT/CyReP/RiotEcc.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

RiotHmac.o: $(OE_PATH)/3rdparty/RIoT/CyReP/RiotHmac.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

RiotKdf.o: $(OE_PATH)/3rdparty/RIoT/CyReP/RiotKdf.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

RiotSha256.o: $(OE_PATH)/3rdparty/RIoT/CyReP/RiotSha256.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

TcpsId.o: $(OE_PATH)/3rdparty/RIoT/CyReP/tcps/TcpsId.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

# tinycbor

cborhelper.o: $(OE_PATH)/3rdparty/RIoT/CyReP/tcps/cborhelper.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

cborencoder.o: $(OE_PATH)/3rdparty/RIoT/External/tinycbor/src/cborencoder.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

cborparser.o: $(OE_PATH)/3rdparty/RIoT/External/tinycbor/src/cborparser.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

# mbedtls

x509_crt.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/x509_crt.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

x509.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/x509.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

md.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/md.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

asn1parse.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/asn1parse.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

md_wrap.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/md_wrap.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

certs.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/certs.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

pem.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/pem.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

sha512.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/sha512.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

ripemd160.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/ripemd160.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

pkparse.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/pkparse.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

md5.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/md5.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

des.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/des.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

base64.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/base64.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

pk.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/pk.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

rsa.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/rsa.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

bignum.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/bignum.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

sha256.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/sha256.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

pk_wrap.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/pk_wrap.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

ecp.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/ecp.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

ecp_curves.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/ecp_curves.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

ecdsa.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/ecdsa.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

rsa_internal.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/rsa_internal.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

asn1write.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/asn1write.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

sha1.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/sha1.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

pkcs5.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/pkcs5.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

hmac_drbg.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/hmac_drbg.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

pkcs12.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/pkcs12.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

oid.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/oid.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

arc4.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/arc4.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

cipher.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/cipher.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

aes.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/aes.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

ccm.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/ccm.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

gcm.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/gcm.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

cipher_wrap.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/cipher_wrap.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

blowfish.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/blowfish.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

camellia.o: $(OE_PATH)/3rdparty/mbedtls/mbedtls/library/camellia.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

# Untrusted/linux

%.o: %.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	@rm -f $(LIB_NAME) $(OBJECTS)
	@echo "Done."
