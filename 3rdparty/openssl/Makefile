include ../../mak/defs.mak

TARGET=$(LIBDIR)/enclave/libcrypto.a

OPENSSLSRCDIR=openssl

CCOPT += gcc 
CCOPT += -fPIC 
CCOPT += -fno-builtin-function
CCOPT += -include $(CURDIR)/stubs.h 
CCOPT += -U_FORTIFY_SOURCE

build: openssl configure
	$(MAKE) -C openssl build_crypto CC="$(CCOPT)"
	mkdir -p $(LIBDIR)
	$(MAKE) install

clean:
	@ $(MAKE) -s clean-silent

clean-silent:
	-@ $(MAKE) -C openssl clean 2> /dev/null > /dev/null

distclean: clean
	@ rm -rf openssl

INSTALL=$(CURDIR)/install

##==============================================================================
##
## configure:
##
##==============================================================================

configure: openssl/include/openssl

openssl/include/openssl:
	( cd openssl; ./config --prefix=$(INSTALL) --openssldir=$(INSTALL) )
	touch .configure

##==============================================================================
##
## install:
##
##==============================================================================

install:
	cp openssl/libcrypto.a $(LIBDIR)/enclave/libecrypto.a
	rm -rf $(INCDIR)/enclave/openssl
	cp -L -r openssl/include/openssl $(INCDIR)/enclave/openssl

##==============================================================================
##
## openssl:
##
##==============================================================================

OPENSSL_VERSION=1.0.2l
OPENSSL_BASE=openssl-$(OPENSSL_VERSION)
OPENSSL_TARBALL=$(OPENSSL_BASE).tar.gz

openssl:
	rm -rf openssl
	wget https://www.openssl.org/source/$(OPENSSL_TARBALL)
	tar zxf $(OPENSSL_TARBALL)
	mv $(OPENSSL_BASE) openssl
	rm -f $(OPENSSL_TARBALL)

