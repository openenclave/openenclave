# set default build type and sanitize
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug;Release;RelWithDebInfo")

string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE)
if(NOT DEFINED CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE})
	message(FATAL_ERROR "Unknown CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
endif()

# Use ccache if available
find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
	set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
	set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
	message("Using ccache")
else()
	message("ccache not found")
endif(CCACHE_FOUND)

if(("${CMAKE_CXX_COMPILER_ID}" MATCHES "GNU") OR ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang"))
	# Enables all the warnings about constructions that some users consider questionable,
	# and that are easy to avoid. Treat at warnings-as-errors, which forces developers
	# to fix warnings as they arise, so they don't accumulate "to be fixed later".
	add_compile_options(-Wall -Werror)

elseif(MSVC)
	# MSVC options go here
endif()
