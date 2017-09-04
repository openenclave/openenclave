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

