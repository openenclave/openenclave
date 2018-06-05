# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

ifndef OPENENCLAVE_CONFIG
$(error Please define the OPENENCLAVE_CONFIG environment variable manually or by sourcing the installed OpenEnclave 'environment' file)
endif

.PHONY: run

define NEWLINE


endef

DIRS = attestation sort

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NEWLINE) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NEWLINE) )

run-silent:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) run $(NEWLINE) )

run:
	$(MAKE) -s run-silent

world: clean build run
