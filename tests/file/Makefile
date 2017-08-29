include ../../mak/defs.mak
DIRS = enc host

define NL


endef

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

ifdef SIM
ENCLAVE=enc/fileenc.so
else
ENCLAVE=enc/fileenc.signed.so
endif

tests:
	host/filehost $(ENCLAVE)

gdb:
	gdb host/filehost -x gdb.commands

gen:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) gen $(NL) )
