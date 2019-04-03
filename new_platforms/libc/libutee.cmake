set(LIBUTEE_S_SRC
    ${LIBUTEE_SRC}/arch/arm/utee_syscalls_a64.S
    ${LIBUTEE_SRC}/arch/arm/gprof/gprof_a64.S)
set(LIBUTEE_S_SRC ${LIBUTEE_SRC} PARENT_SCOPE)

set(LIBUTEE_C_SRC
    ${LIBUTEE_SRC}/tee_api_property.c
    ${LIBUTEE_SRC}/abort.c
    #${LIBUTEE_SRC}/trace_ext.c
    ${LIBUTEE_SRC}/assert.c
    ${LIBUTEE_SRC}/base64.c
    #${LIBUTEE_SRC}/tee_api_arith.c
    ${LIBUTEE_SRC}/tee_api.c
    ${LIBUTEE_SRC}/tee_api_objects.c
    ${LIBUTEE_SRC}/tee_api_operations.c
    ${LIBUTEE_SRC}/tee_api_se.c
    ${LIBUTEE_SRC}/tee_api_panic.c
    ${LIBUTEE_SRC}/tee_tcpudp_socket.c
    ${LIBUTEE_SRC}/tee_socket_pta.c
    ${LIBUTEE_SRC}/arch/arm/user_ta_entry.c
    ${LIBUTEE_SRC}/arch/arm/utee_misc.c
    ${LIBUTILS_EXT_SRC}/snprintk.c
    ${LIBUTILS_EXT_SRC}/buf_compare_ct.c
    ${CMAKE_CURRENT_LIST_DIR}/enc/optee/link.c)
set(LIBUTEE_C_SRC ${LIBUTEE_C_SRC} PARENT_SCOPE)
