#!/usr/bin/make -f

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

SDK_VERSION=sgx_2.10_reproducible
DCAP_VERSION=dcap_1.7_reproducible

all: update-sgxsdk-headers
	echo All done - please review changes

update-sgxsdk-headers:
	rm -rf include
	mkdir -p include
	( cd include; wget https://raw.githubusercontent.com/intel/linux-sgx/$(SDK_VERSION)/common/inc/sgx_uae_quote_ex.h )
	( cd include; wget https://raw.githubusercontent.com/intel/linux-sgx/$(SDK_VERSION)/common/inc/sgx_defs.h )
	( cd include; wget https://raw.githubusercontent.com/intel/linux-sgx/$(SDK_VERSION)/common/inc/sgx_error.h )
	( cd include; wget https://raw.githubusercontent.com/intel/linux-sgx/$(SDK_VERSION)/common/inc/sgx_urts.h )
	( cd include; wget https://raw.githubusercontent.com/intel/linux-sgx/$(SDK_VERSION)/common/inc/sgx_eid.h )
	( cd include; wget https://raw.githubusercontent.com/intel/linux-sgx/$(SDK_VERSION)/common/inc/sgx_quote.h )
	( cd include; wget https://raw.githubusercontent.com/intel/linux-sgx/$(SDK_VERSION)/common/inc/sgx_key.h )
	( cd include; wget https://raw.githubusercontent.com/intel/linux-sgx/$(SDK_VERSION)/common/inc/sgx_attributes.h )
	( cd include; wget https://raw.githubusercontent.com/intel/linux-sgx/$(SDK_VERSION)/common/inc/sgx_report.h )
	( cd include; wget https://raw.githubusercontent.com/intel/SGXDataCenterAttestationPrimitives/$(DCAP_VERSION)/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h )
	( cd include; wget https://raw.githubusercontent.com/intel/SGXDataCenterAttestationPrimitives/$(DCAP_VERSION)/QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h )
	( cd include; wget https://raw.githubusercontent.com/intel/SGXDataCenterAttestationPrimitives/$(DCAP_VERSION)/QuoteGeneration/pce_wrapper/inc/sgx_pce.h )
