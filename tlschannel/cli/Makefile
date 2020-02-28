# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

MBEDTLS_LIBDIR=/usr/lib/x86_64-linux-gnu

ifeq ($(shell ls $(MBEDTLS_LIBDIR)/libmbedtls.a 2> /dev/null),)
$(error "mbedtls not found under $(MBEDTLS_LIBDIR): please install mbedtls-dev")
endif

CFLAGS=-Wall -Werror -O2
LIBS=-L$(MBEDTLS_LIBDIR) -lmbedtls -lmbedx509 -lmbedcrypto

all:
	gcc $(CFLAGS) -o tlscli cli.c tlscli.c $(LIBS)

clean:
	rm -f tlscli
