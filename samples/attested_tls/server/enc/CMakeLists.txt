# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(OUTPUT tls_server_t.h tls_server_t.c tls_server_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/server/tls_server.edl
  COMMAND openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/server/tls_server.edl)

# Sign enclave
add_custom_command(OUTPUT tls_server_enc.signed
  DEPENDS tls_server_enc enc.conf ${CMAKE_BINARY_DIR}/server/enc/server_private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:tls_server_enc> -c ${CMAKE_SOURCE_DIR}/server/enc/enc.conf -k ${CMAKE_BINARY_DIR}/server/enc/server_private.pem)

add_executable(tls_server_enc
	       ecalls.cpp
	       crypto.cpp
	       server.cpp
	       cert_verifier.cpp
	       identity_verifier.cpp
	       ../../common/utility.cpp
	       ${CMAKE_CURRENT_BINARY_DIR}/tls_server_t.c)

target_compile_definitions(tls_server_enc PUBLIC OE_API_VERSION=2)

target_include_directories(tls_server_enc PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_BINARY_DIR}/server/enc)

target_link_libraries(tls_server_enc
		openenclave::oeenclave
		openenclave::oelibcxx
		openenclave::oehostsock
		openenclave::oehostresolver)

add_custom_target(tls_server_sign_enc ALL DEPENDS tls_server_enc.signed)
add_dependencies(tls_server_enc build_common)
