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

ENCLAVE = ./enc/reportenc.signed.so

tests:
ifneq ($(OE_SIMULATION),1)
	host/reporthost $(ENCLAVE)
endif

mc:
	$(MEMCHECK) host/reporthost $(ENCLAVE)

elf:
	$(MAKE) -C enc elf

gdb:
	gdb host/reporthost -x gdb.commands
