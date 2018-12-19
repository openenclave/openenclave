add_library(oehost_opteesim STATIC uOptee.c)

target_include_directories(oehost_opteesim PRIVATE ${OE_PATH}/include)
target_include_directories(oehost_opteesim PRIVATE ${NP_PATH}/include/optee/host/Simulator)
target_include_directories(oehost_opteesim PRIVATE ${NP_PATH}/include)
target_include_directories(oehost_opteesim PRIVATE ${OPTEE_OS_PATH}/lib/libutee/include)
target_include_directories(oehost_opteesim PRIVATE ${OPTEE_OS_PATH}/lib/libutils/ext/include)
target_include_directories(oehost_opteesim PRIVATE ${OPTEE_CALLS_PATH}/OpteeCalls/inc)
target_include_directories(oehost_opteesim PRIVATE ${WDK_PATH}/km)
