# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

#MBEDTLS_LIBDIR=/usr/lib/x86_64-linux-gnu
MBEDTLS_LIBDIR= /home/mike/mbedtls/library
#MBEDTLS_LIBDIR=/home/mike/openenclave/build/3rdparty/mbedtls

ifeq ($(shell ls $(MBEDTLS_LIBDIR)/libmbedtls.a 2> /dev/null),)
$(error "mbedtls not found under $(MBEDTLS_LIBDIR): please install mbedtls-dev")
endif

CFLAGS=-Wall -Werror -O2

INCLUDES += -I/opt/openenclave/include

OE_LIBDIR=/opt/openenclave/lib/openenclave/enclave
LIBS += $(OE_LIBDIR)/liboeenclave.a
LIBS += $(OE_LIBDIR)/liboecryptombed.a

LIBS += -L$(MBEDTLS_LIBDIR)
LIBS += -lmbedtls
LIBS += -lmbedx509
LIBS += -lmbedcrypto

all:
	gcc $(CFLAGS) $(INCLUDES) -o tlscli cli.c tlscli.c $(LIBS) stubs.c rdrand.S

clean:
	rm -f tlscli
