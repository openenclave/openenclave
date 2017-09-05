include ../mak/defs.mak

DIRS += mbedtls
DIRS += dlmalloc
DIRS += musl
DIRS += libcxxrt
DIRS += libunwind
DIRS += libcxx
DIRS += mergecxx
#DIRS += openssl

define NL


endef

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

distclean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) distclean $(NL) )

depend:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) depend $(NL) )

CLOC += $(shell find . -name '*.cpp')
CLOC += $(shell find . -name '*.h')
CLOC += $(shell find . -name '*.cc')
CLOC += $(shell find . -name '*.c')
CLOC += $(shell find . -name '*.h')
CLOC += $(shell find . -name '*.hpp')
CLOC += $(wildcard libcxx/trunk/include/*)

cloc:
	cloc $(CLOC)
