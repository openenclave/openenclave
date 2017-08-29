include ../../mak/defs.mak
DIRS = SampleAppCRT SampleAppCRTHost

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NEWLINE) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NEWLINE) )

tests:
	SampleAppCRTHost/SampleAppCRTHost SampleAppCRT/SampleAppCRT.signed.so
