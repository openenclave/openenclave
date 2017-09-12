include ../../mak/defs.mak
DIRS = SampleAppAttestation SampleAppAttestationHost

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NEWLINE) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NEWLINE) )
	rm -f SampleAppEnclaveQuote.bin

depend:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) depend $(NEWLINE) )

tests:
ifneq ($(OE_SIMULATION),1)
	SampleAppAttestationHost/SampleAppAttestationHost SampleAppAttestation/SampleAppAttestation.signed.so
endif

mc:
	$(MEMCHECK) SampleAppAttestationHost/SampleAppAttestationHost SampleAppAttestation/SampleAppAttestation.signed.so
