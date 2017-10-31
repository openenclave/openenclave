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

ENCLAVE = ./enc/printenc.signed.so

tests:
	@ host/printhost $(ENCLAVE) > $(TMPDIR)/printhost.stdout
	@ diff $(TMPDIR)/printhost.stdout printhost.stdout
	@ host/printhost $(ENCLAVE) 2> $(TMPDIR)/printhost.stderr
	@ diff $(TMPDIR)/printhost.stderr printhost.stderr

mc:
	$(MEMCHECK) host/printhost $(ENCLAVE)

elf:
	$(MAKE) -C enc elf

gdb:
	gdb host/printhost -x gdb.commands

size:
	size $(ENCLAVE)
