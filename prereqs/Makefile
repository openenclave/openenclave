# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

ifdef USE_AESM
	DIRS = packages isgx aesm
else
	DIRS = sgx-driver ngsa
endif

define NL


endef

all:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )

install:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) install $(NL) )

uninstall:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) uninstall $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

distclean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) distclean $(NL) )
