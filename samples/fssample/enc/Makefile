# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all:
	/opt/openenclave/bin/oeedger8r --trusted ../sample.edl
	oe-enclave-gcc -c enc.c sample_t.c
	musl-gcc -fPIE -c main.c
	oe-enclave-gcc -o sampleenc enc.o main.o sample_t.o

clean:
	rm -f sampleenc enc.o main.o sample*
