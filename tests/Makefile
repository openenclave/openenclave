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
DIRS += thread
DIRS += pingpong 
DIRS += file
DIRS += tester
DIRS += stdc
DIRS += stdcxx
DIRS += mbed
DIRS += report
DIRS += SampleAppAttestation 
DIRS += ricochet

define NL


endef

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

tests:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )

sgx-tests:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) tests SGX=1 $(NL) )

sim-tests:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) tests SIM=1 $(NL) )

all-tests: sgx-tests sim-tests

depend:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) depend $(NL) )

GENDIRS = tester typeinfo pingpong file

gen:
	@ $(foreach i, $(GENDIRS), $(MAKE) -s -C $(i) gen $(NL) )
