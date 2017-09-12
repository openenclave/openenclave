#ifndef _ASMDEFS_H
#define _ASMDEFS_H

#ifndef __ASSEMBLER__
#include <openenclave/types.h>
#include <stdint.h>
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

#ifndef __ASSEMBLER__
int __OE_DispatchOCall(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg1Out,
    uint64_t* arg2Out,
    void* tcs);
#endif

#endif /* _ASMDEFS_H */
