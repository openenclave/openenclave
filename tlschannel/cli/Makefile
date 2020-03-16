# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

MBEDTLS_LIBDIR=/usr/lib/x86_64-linux-gnu
#MBEDTLS_LIBDIR=/home/mike/mbedtls/library
#MBEDTLS_LIBDIR=/home/mike/openenclave/build/3rdparty/mbedtls

ifeq ($(shell ls $(MBEDTLS_LIBDIR)/libmbedtls.a 2> /dev/null),)
$(error "mbedtls not found under $(MBEDTLS_LIBDIR): please install mbedtls-dev")
endif

CFLAGS=-Wall -Werror -g

INCLUDES += -I/opt/openenclave/include

LIBS += -L$(MBEDTLS_LIBDIR)
LIBS += -lmbedtls
LIBS += -lmbedx509
LIBS += -lmbedcrypto

all:
	gcc $(CFLAGS) $(INCLUDES) -o tlscli cli.c tlscli.c $(LIBS)

clean:
	rm -f tlscli
