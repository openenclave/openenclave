include ../../mak/defs.mak

all:

CFLAGS += -I$(INCDIR)/enclave/libc 
CFLAGS += -nostdinc
CFLAGS += -fPIC
CFLAGS += -fno-builtin-udivti3

export CFLAGS

all: mbedtls configure
	cp config.h ./mbedtls/include/mbedtls/config.h
	$(MAKE) -C mbedtls
	cp ./mbedtls/library/libmbedcrypto.a $(LIBDIR)/enclave/
	rm -rf $(INCDIR)/enclave/mbedtls
	cp -r ./mbedtls/include/mbedtls $(INCDIR)/enclave/mbedtls

configure: .configure

CMAKEFLAGS=-DENABLE_TESTING=Off -DENABLE_PROGRAMS=Off

.configure:
	( cd mbedtls; cmake $(CMAKEFLAGS) CMakeLists.txt -DCMAKE_C_FLAGS="$(CFLAGS)" )
	touch .configure

clean:
	$(MAKE) -s clean-silent

clean-silent:
	-@ $(MAKE) -C mbedtls clean 2> /dev/null

DISTNAME=mbedtls-2.6.0
TARNAME=$(DISTNAME)-apache.tgz

distclean: clean
	rm -rf $(DISTNAME)
	rm -rf $(TARNAME)
	rm -rf mbedtls
	rm -f .configure
	rm -f .configure

mbedtls:
	$(MAKE) wget
	tar zxvf $(TARNAME)
	mv $(DISTNAME) mbedtls
	rm -rf $(TARNAME)

wget:
	rm -rf $(TARNAME)
	wget https://tls.mbed.org/download/$(TARNAME)

clone:
	git clone https://github.com/ARMmbed/mbedtls

diff-config:
	diff config.h ./mbedtls/include/mbedtls/config.h
