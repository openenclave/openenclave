#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ENDIAN_SUFFIX "el"
#else
#define ENDIAN_SUFFIX ""
#endif

#ifdef __mips_soft_float
#define FP_SUFFIX "-sf"
#else
#define FP_SUFFIX ""
#endif

#define LDSO_ARCH "mips" ENDIAN_SUFFIX FP_SUFFIX

#define TPOFF_K (-0x7000)

#define REL_SYM_OR_REL  R_MIPS_REL32
#define REL_PLT         R_MIPS_JUMP_SLOT
#define REL_COPY        R_MIPS_COPY
#define REL_DTPMOD      R_MIPS_TLS_DTPMOD32
#define REL_DTPOFF      R_MIPS_TLS_DTPREL32
#define REL_TPOFF       R_MIPS_TLS_TPREL32

#define NEED_MIPS_GOT_RELOCS 1
#define DYNAMIC_IS_RO 1
#define ARCH_SYM_REJECT_UND(s) (!((s)->st_other & STO_MIPS_PLT))

#define CRTJMP(pc,sp) __asm__ __volatile__( \
	"move $sp,%1 ; jr %0" : : "r"(pc), "r"(sp) : "memory" )
