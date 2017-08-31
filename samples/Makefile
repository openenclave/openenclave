
#export OPENENCLAVE_DATADIR=/opt/openenclave-0.1.0/share/openenclave

ifndef OPENENCLAVE_DATADIR
$(error Please define the OPENENCLAVE_DATADIR environment variable manually or by sourcing the installed OpenEnclave 'environment' file)
endif

DIRS = hello sort

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) ; )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean ; )

tests:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) tests ; )

