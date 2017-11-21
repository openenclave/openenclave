# CMake project for reference manual
#
# Build and install reference manual. Disable with "ENABLE_REFMAN=OFF", such as when do Doxygen is installed.
#
# Target "refman-source" generates md-files into source-tree.
#
option(ENABLE_REFMAN "Enable refman build" ON)

include (ExternalProject)
find_package(Doxygen)

if(ENABLE_REFMAN AND NOT DOXYGEN_FOUND)
	message(FATAL_ERROR "Doxygen not found - specfify no refman refman generation with -DENABLE_REFMAN=OFF")
elseif(NOT ENABLE_REFMAN)
	message("ENABLE_REFMAN disabled, skipping refman generation")
else()
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/doxygen.conf ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)

	ExternalProject_Add(refman
		DOWNLOAD_COMMAND ""
		COMMENT "Generating refman HTML documentation"
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
		INSTALL_COMMAND $(CMAKE_COMMAND) -E copy_directory
			html ${OE_DOCDIR}/openenclave/html
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	)
	install (DIRECTORY ${OE_DOCDIR}/openenclave/html DESTINATION ${CMAKE_INSTALL_DOCDIR})


	# Custom target to update .md-files in source tree. Invoke manually if desired.
	message("Use target 'refman-source' to populate refman *.md-files into source tree")
	add_custom_target(refman-source
		DEPENDS refman
		COMMAND dox2md ${CMAKE_CURRENT_BINARY_DIR}/xml/index.xml
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/md
		COMMENT "Generating refman documentation into source-tree" VERBATIM
	)
endif()
