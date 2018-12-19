add_library(oeenclave_opteesim STATIC
    ${CYREP_PATH}/tcps/TcpsId.c
    ${TINYCBOR_PATH}/src/cborencoder.c
    ${TINYCBOR_PATH}/src/cborparser.c
    cyres_sim.c
    memory-sim.c
    stdio-sim.c
    tcrypto-sim.c
    tobject-sim.c
    trpc_sim.c
    ttime-sim.c)

target_include_directories(oeenclave_opteesim PRIVATE ${OE_PATH}/include)
target_include_directories(oeenclave_opteesim PRIVATE ${NP_PATH}/include/optee/enclave/Simulator)
target_include_directories(oeenclave_opteesim PRIVATE ${NP_PATH}/include/optee/enclave)
target_include_directories(oeenclave_opteesim PRIVATE ${NP_PATH}/include/optee)
target_include_directories(oeenclave_opteesim PRIVATE ${CYREP_PATH}/cyrep)
target_include_directories(oeenclave_opteesim PRIVATE ${CYREP_PATH}/tcps)
target_include_directories(oeenclave_opteesim PRIVATE ${TINYCBOR_PATH}/src)
target_include_directories(oeenclave_opteesim PRIVATE ${OPTEE_OS_PATH}/lib/libutee/include)
target_include_directories(oeenclave_opteesim PRIVATE ${OPTEE_OS_PATH}/lib/libutils/ext/include)
