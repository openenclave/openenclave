#ifndef _ASMDEFS_H
#define _ASMDEFS_H

#ifndef __ASSEMBLER__
#include <oecommon/types.h>
#endif

#ifdef __ASSEMBLER__
# define ENCLU_EENTER 2
#endif

#ifndef __ASSEMBLER__
void OE_Enter(
    void* tcs,
    void (*aep)(void),
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4);
#endif

#ifndef __ASSEMBLER__
void OE_EnterSim(
    void* tcs,
    void (*aep)(void),
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4);
#endif

#endif /* _ASMDEFS_H */
