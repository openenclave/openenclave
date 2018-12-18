add_library(oehost_opteesim STATIC uOptee.c)

target_include_directories(oehost_opteesim PRIVATE ${OE_PATH}/include)
target_include_directories(oehost_opteesim PRIVATE ${OPTEE_CALLS_PATH}/OpteeCalls/inc)
target_include_directories(oehost_opteesim PRIVATE ${OPTEE_OS_PATH}/lib/libutee/include)
