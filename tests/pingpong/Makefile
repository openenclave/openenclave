include ../../mak/defs.mak
DIRS = enc host

define NL


endef

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

depend:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) depend $(NEWLINE) )

gen:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) gen $(NL) )

tests:
	host/pingponghost enc/pingpongenc.signed.so
