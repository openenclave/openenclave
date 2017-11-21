# deploy OE main include files, add interface library, add install steps

# Deployment is actually only for samples. The remainder of the tree uses the
# OE-includes from their original source-tree location. Hoever, the samples
# assumes the combined include-tree. Modifying the include-tree in the sample
# would be wrong, so we build it here.
#
# Use ExternalProject for its build-states. It is not ideal, though a custom
# command would either require listing all known headers, or would be
#  unreliable.
include (ExternalProject)
ExternalProject_Add(oe_includes_place
	DOWNLOAD_COMMAND ""
	CONFIGURE_COMMAND ""
	BUILD_COMMAND ${CMAKE_COMMAND} -E copy_directory
		${CMAKE_CURRENT_LIST_DIR}/openenclave ${OE_INCDIR}/openenclave
	INSTALL_COMMAND ""
	)

add_library(oe_includes INTERFACE)
add_dependencies(oe_includes oe_includes_place)
target_include_directories(oe_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
install (DIRECTORY openenclave DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
