include ../../mak/defs.mak
DIRS = SampleApp SampleAppHost

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NEWLINE) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NEWLINE) )

depend:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) depend $(NEWLINE) )

tests:
	SampleAppHost/SampleAppHost SampleApp/SampleApp.signed.so
