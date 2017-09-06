include ../mak/defs.mak
.PHONY: tests

ifdef HAVE_SGX
DIRS += aesm
endif

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

ifdef HAVE_SGX
  DIRS += report
  DIRS += SampleAppAttestation 
endif

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
