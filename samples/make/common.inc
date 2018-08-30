# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

CXXFLAGS = 

ifeq ($(APPLY_SPECTRE_1_LLVM_MITIGATION),1)
	CXXFLAGS += -mllvm -spectre-loop-hardening -mllvm -x86-spectre-mitigation -mllvm msr
endif
