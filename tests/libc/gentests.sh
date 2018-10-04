#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

files=$(cat tests.supported)

##==============================================================================
##
## Remove all previously generated files.
##
##==============================================================================

tests_c=enc/tests.c
tests_cmake=enc/tests.cmake

rm -f enc/test_*.c
rm -f ${tests_cmake}
rm -f ${tests_c}

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
## Generate tests.cpp
##
##==============================================================================


rm -rf ${tests_c} ${tests_cmake}

cat >> ${tests_cmake} <<END
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(TESTS
END

cat >> ${tests_c} <<END
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "tests.h"

extern int run_test(
    const char* name,
    int (*main)(int argc, const char* argv[]));

int run_tests(void)
{
    int ret = 0;
END

for i in ${files}
do
    name=$(get_test_name "${i}")

cat >> ${tests_cmake} <<END
${name}.c
END

cat >> ${tests_c} <<END
    extern int ${name}(int argc, const char* argv[]);
    ret += run_test("${name}", ${name});
END

done

cat >> ${tests_cmake} <<END
)
END

cat >> ${tests_c} <<END
    return ret;
}
END

echo "Created ${tests_c}"
