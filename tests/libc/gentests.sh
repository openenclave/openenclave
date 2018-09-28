#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

files=$(cat tests.supported)

##==============================================================================
##
## Remove all previously generated files.
##
##==============================================================================

tests_h=enc/tests.h
tests_cpp=enc/tests.cpp
tests_cmake=enc/tests.cmake

rm -f enc/test_*.c
rm -f ${tests_cmake}
rm -f ${tests_h}
rm -f ${tests_cpp}

##==============================================================================
##
## get_test_name()
##
##     Convert a path to a test name that is suitable as a C identifier.
##
##==============================================================================

get_test_name()
{
    name=$(echo "$1" | sed "s~[\.\/\-]~_~g" | sed "s~______3rdparty_musl_libc_test_src_~test_~g")
    echo "${name}"
}

##==============================================================================
##
## Generate the individual test source files.
##
##==============================================================================

for i in ${files}
do
    name=$(get_test_name "${i}")
    source_file=enc/${name}.c
cat > "${source_file}" <<END
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define main ${name}
#include "../${i}"
END
    echo "Created ${source_file}"
done

##==============================================================================
##
## Generate tests.h and tests.cpp
##
##==============================================================================


rm -rf ${tests_h} ${tests_cpp} ${tests_cmake}

cat >> ${tests_cmake} <<END
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(TESTS
END

cat >> ${tests_h} <<END
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

END

cat >> ${tests_cpp} <<END
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

END

for i in ${files}
do
    name=$(get_test_name "${i}")

cat >> ${tests_h} <<END
extern "C" int ${name}(int argc, const char* argv[]);
END

cat >> ${tests_cmake} <<END
${name}.c
END

cat >> ${tests_cpp} <<END
RUN_TEST(${name});
END

done

cat >> ${tests_cmake} <<END
)
END

echo ${tests_h}
echo ${tests_cpp}
