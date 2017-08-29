include ../../mak/defs.mak

.PHONY: lib

TARGET = $(LIBDIR)/tmp/libcxx.a

all:
	$(MAKE) -C src
	$(MAKE) install

INSTALL_DIR=$(INCDIR)/enclave/cxx

clean:
	$(MAKE) -C src clean
	rm -rf $(INSTALL_DIR)
	rm -rf $(TARGET)

tests:

install:
	rm -rf $(INSTALL_DIR)
	cp -r include $(INSTALL_DIR)

distclean:
