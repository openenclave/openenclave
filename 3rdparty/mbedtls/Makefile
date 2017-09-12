include ../../mak/defs.mak

TARGET=$(INCDIR)/openenclave/oe-mbedtls

CACHEFILE = $(CACHEDIR)/mbedtls.tar.gz

all:

CFLAGS += -I$(INCDIR)/openenclave/libc 
CFLAGS += -nostdinc
CFLAGS += -fPIC
CFLAGS += -fno-builtin-udivti3

export CFLAGS

all: mbedtls configure .build

.build:
	cp config.h ./mbedtls/include/mbedtls/config.h
	$(MAKE) -C mbedtls
	cp ./mbedtls/library/libmbedcrypto.a $(LIBDIR)/enclave/
	rm -rf $(TARGET)
	mkdir -p $(TARGET)
	cp -L -r ./mbedtls/include/mbedtls $(TARGET)
	touch .build

configure: .configure

CMAKEFLAGS=-DENABLE_TESTING=Off -DENABLE_PROGRAMS=Off

.configure:
	( cd mbedtls; cmake $(CMAKEFLAGS) CMakeLists.txt -DCMAKE_C_FLAGS="$(CFLAGS)" )
	touch .configure

clean:
	@ $(MAKE) -s clean-silent
	@ rm -f .build

clean-silent:
	-@ $(MAKE) -C mbedtls clean 2> /dev/null
	@ rm -rf $(TARGET)

MBBEDDIST=mbedtls-2.6.0
TARNAME=$(MBBEDDIST)-apache.tgz

distclean: clean
	rm -rf $(MBBEDDIST)
	rm -rf $(TARNAME)
	rm -rf mbedtls
	rm -f .configure
	rm -f .configure

mbedtls:
	$(MAKE) $(CACHEFILE)
	tar zxf $(CACHEFILE)

$(CACHEFILE):
	$(MAKE) wget
	tar zxvf $(TARNAME)
	mv $(MBBEDDIST) mbedtls
	rm -rf $(TARNAME)
	tar zcf $(CACHEFILE) mbedtls
	rm -rf mbedtls

wget:
	rm -rf $(TARNAME)
	wget https://tls.mbed.org/download/$(TARNAME)

clone:
	git clone https://github.com/ARMmbed/mbedtls

diff-config:
	diff config.h ./mbedtls/include/mbedtls/config.h

depend:
