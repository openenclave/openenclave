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

distclean: clean
	rm -rf mbedtls
	rm -f .configure

mbedtls:
	git clone https://github.com/ARMmbed/mbedtls


diff-config:
	diff config.h ./mbedtls/include/mbedtls/config.h
