include ../mak/defs.mak
.PHONY: tests

DIRS += aesm
DIRS += SampleAppCRT
DIRS += SampleApp
DIRS += echo 
eIRS += mem
DIRS += typeinfo
DIRS += load
DIRS += str
DIRS += mem
DIRS += ecall
DIRS += ocall
DIRS += report
DIRS += thread
DIRS += pthread
DIRS += pingpong 
DIRS += file
DIRS += tester
DIRS += stdc
DIRS += stdcxx
DIRS += SampleAppAttestation 
DIRS += malloc
DIRS += crypto

define NL


endef

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

tests:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )

depend:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) depend $(NL) )

GENDIRS = tester typeinfo pingpong file

gen:
	@ $(foreach i, $(GENDIRS), $(MAKE) -s -C $(i) gen $(NL) )
