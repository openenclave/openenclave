# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

.PHONY: run

define NEWLINE


endef

# Obtain list of installed samples.
DIRS = $(wildcard */)

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NEWLINE) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NEWLINE) )

run-silent:
	@ $(foreach i, $(DIRS), $(MAKE) -C $(i) run $(NEWLINE) )

run:
	$(MAKE) -s run-silent

world: clean build run
