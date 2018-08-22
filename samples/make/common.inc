# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

CXXFLAGS = 

ifeq ($(APPLY_SPECTRE_1_LLVM_MITIGATION),1)
	CXXFLAGS += -mllvm -x86-speculative-load-hardening
endif
