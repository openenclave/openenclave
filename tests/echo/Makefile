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
	host/echohost ./enc/echoenc.signed.so

size:
	size ./enc/echoenc.signed.so

gdb:
	gdb ./host/echohost -x gdb.commands

rebuild:
	( cd $(TOP)/host; $(MAKE) clean; $(MAKE) )
	( cd $(TOP)/enclave ; $(MAKE) clean; $(MAKE) )
	$(MAKE) clean
	$(MAKE)
