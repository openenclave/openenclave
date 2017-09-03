include ../mak/defs.mak

DIRS += dlmalloc
DIRS += musl
DIRS += libcxxrt
DIRS += libunwind
DIRS += libcxx
DIRS += mergecxx
DIRS += openssl
DIRS += mbedtls

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

