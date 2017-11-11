#define LDSO_ARCH "powerpc"

#define TPOFF_K (-0x7000)

#define REL_SYMBOLIC    R_PPC_ADDR32
#define REL_GOT         R_PPC_GLOB_DAT
#define REL_PLT         R_PPC_JMP_SLOT
#define REL_RELATIVE    R_PPC_RELATIVE
#define REL_COPY        R_PPC_COPY
#define REL_DTPMOD      R_PPC_DTPMOD32
#define REL_DTPOFF      R_PPC_DTPREL32
#define REL_TPOFF       R_PPC_TPREL32

#define CRTJMP(pc,sp) __asm__ __volatile__( \
	"mr 1,%1 ; mtlr %0 ; blr" : : "r"(pc), "r"(sp) : "memory" )
