include ../../mak/defs.mak

DIRS = enc host

define NL


endef

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

depend:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) depend $(NL) )

tests:
	host/ricochethost ./enc/ricochetenc.signed.so

size:
	size ./enc/ricochetenc.signed.so

gdb:
	gdb ./host/ricochethost -x gdb.commands

rebuild:
	( cd $(TOP)/host; $(MAKE) clean; $(MAKE) )
	( cd $(TOP)/enclave ; $(MAKE) clean; $(MAKE) )
	$(MAKE) clean
	$(MAKE)
