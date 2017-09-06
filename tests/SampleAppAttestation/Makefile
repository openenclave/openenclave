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
	SampleAppAttestationHost/SampleAppAttestationHost SampleAppAttestation/SampleAppAttestation.signed.so

mc:
	$(MEMCHECK) SampleAppAttestationHost/SampleAppAttestationHost SampleAppAttestation/SampleAppAttestation.signed.so
