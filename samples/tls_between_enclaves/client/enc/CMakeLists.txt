# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(OUTPUT tls_client_t.h tls_client_t.c tls_client_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/client/tls_client.edl
  COMMAND openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/client/tls_client.edl)

# Sign enclave
add_custom_command(OUTPUT tls_client_enc.signed
  DEPENDS tls_client_enc enc.conf
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:tls_client_enc> -c ${CMAKE_SOURCE_DIR}/client/enc/enc.conf -k ${CMAKE_SOURCE_DIR}/client/enc/client_signing_private.pem)

add_executable(tls_client_enc ecalls.cpp crypto.cpp client.cpp identity_verifier.cpp cert_verifier.cpp ../../common/utility.cpp ${CMAKE_CURRENT_BINARY_DIR}/tls_client_t.c)
target_compile_definitions(tls_client_enc PUBLIC OE_API_VERSION=2)

target_include_directories(tls_client_enc PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR} # Needed for #include "../shared.h"
  ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(tls_client_enc
		openenclave::oeenclave
		openenclave::oelibcxx
                openenclave::mbedtls
		openenclave::mbedcrypto
		openenclave::oehostsock
		openenclave::oehostresolver
                openenclave::oecore
	        openenclave::oelibc
	        openenclave::oeposix)

add_custom_target(tls_client_sign_enc ALL DEPENDS tls_client_enc.signed)
