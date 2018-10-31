POINTER_SIZE = 8

# These constant definitions must align with _oe_enclave structure defined in host\enclave.h
OE_ENCLAVE_MAGIC_FIELD = 0
OE_ENCLAVE_ADDR_FIELD = 2
OE_ENCLAVE_HEADER_LENGTH = 0X28
OE_ENCLAVE_HEADER_FORMAT = 'QQQQQ'
OE_ENCLAVE_MAGIC_VALUE = 0x20dc98463a5ad8b8

# The following are the offset of the 'debug' and
# 'simulate' flag fields which must lie one after the other.
OE_ENCLAVE_FLAGS_OFFSET = 0x598
OE_ENCLAVE_FLAGS_LENGTH = 2
OE_ENCLAVE_FLAGS_FORMAT = 'BB'
OE_ENCLAVE_THREAD_BINDING_OFFSET = 0x28

# These constant definitions must align with ThreadBinding structure defined in host\enclave.h
THREAD_BINDING_SIZE = 0x28
THREAD_BINDING_HEADER_LENGTH = 0X8
THREAD_BINDING_HEADER_FORMAT = 'Q'

# This constant definition must align with the OE enclave layout.
TD_OFFSET_FROM_TCS =  0X4000

# This constant definition must align with TD structure in internal\sgxtypes.h.
TD_CALLSITE_OFFSET = 0XF0

# This constant definition must align with Callsite structure in enclave\td.h.
CALLSITE_OCALLCONTEXT_OFFSET = 0X40

# These constant definitions must align with OCallContext structure in enclave\td.h.
OCALLCONTEXT_LENGTH = 2 * 8
OCALLCONTEXT_FORMAT = 'QQ'
OCALLCONTEXT_RBP = 0
OCALLCONTEXT_RET = 1