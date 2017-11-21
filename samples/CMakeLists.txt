# Copy sample sources and build out-of-tree
include (ExternalProject)
ExternalProject_Add(samples
	DEPENDS oelibc oelibcxx

	DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E copy_directory
		${CMAKE_CURRENT_LIST_DIR} <SOURCE_DIR>
	    COMMAND ${CMAKE_COMMAND} -E remove <SOURCE_DIR>/CMakeLists.txt

	CONFIGURE_COMMAND ""

	BUILD_COMMAND make -C <SOURCE_DIR> OPENENCLAVE_CONFIG=<TMP_DIR>/config.mak

	INSTALL_COMMAND ""
	)
# oesign not yet defined, so use add_dependencies
add_dependencies(samples oesign)

# generate config.mk for sample build consumption
ExternalProject_Get_Property(samples tmp_dir)
gen_config_file(${tmp_dir}/config.mak "${OE_OUTPUT_DIR}")

# install the samples w/o this very CMakeLists.txt
install (DIRECTORY ${CMAKE_CURRENT_LIST_DIR} 
	DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave
	PATTERN CMakeLists.txt EXCLUDE
	)

# include in test
ExternalProject_Get_Property(samples source_dir)
add_test(samples make -C ${source_dir} run OPENENCLAVE_CONFIG=${tmp_dir}/config.mak)
