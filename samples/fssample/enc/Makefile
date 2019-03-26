# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all:
	/opt/openenclave/bin/oeedger8r --trusted ../sample.edl
	oe-enclave-gcc -o sampleenc enc.c main.c sample_t.c

clean:
	rm -f sampleenc enc.o main.o sample*
