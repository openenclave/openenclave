#ifndef _OE_HOST_ENCLAVE_H
#define _OE_HOST_ENCLAVE_H

#include <openenclave/host.h>
#include <stdbool.h>
#include <openenclave/bits/build.h>
#include <openenclave/bits/sgxtypes.h>

#define ENCLAVE_MAGIC 0x20dc98463a5ad8b8

typedef struct _ECallNameAddr
{
    /* Name of ECALL function */
    char* name;

    /* Virtual address of ECALL function */
    uint64_t vaddr;
}
ECallNameAddr;

/* Enclave thread data */
typedef struct _ThreadData
{
    /* Address of the enclave's thread control structure */
    uint64_t tcs;

    /* Whether this slot is busy */
    bool busy;

    /* The thread this slot is assigned to */
    OE_Thread thread;

    /* The number of times caller thread has been assigned this ThreadData */
    uint64_t count;

    /* Event object for enclave threading implementation */
    uint32_t event;
}
ThreadData;

/* Get thread data from thread-specific data (TSD) */
ThreadData* GetThreadData(void);

struct _OE_Enclave
{
    /* A "magic number" to validate structure */
    uint64_t magic;

    /* Path of the enclave file */
    char* path;

    /* Base address of enclave within enclave address space (BASEADDR) */
    uint64_t addr;

    /* Address of .text section (for gdb) */
    uint64_t text;

    /* Size of enclave in bytes */
    uint64_t size;

    /* Array of ThreadData slots */
    ThreadData tds[OE_SGX_MAX_TCS];
    size_t num_tds;
    OE_Spinlock lock;

    /* Hash of enclave (MRENCLAVE) */
    OE_SHA256 hash;

    /* Array of ECALL entry points */
    ECallNameAddr* ecalls;
    size_t num_ecalls;

    /* Debug mode */
    bool debug;

    /* Simulation mode */
    bool simulate;
};

/* Get enclave from thread-specific data (TSD) */
OE_Enclave* GetEnclave(void);

/* Set enclave into thread-specific data (TSD) */
void SetEnclave(OE_Enclave* enclave);

/* Get the event for the given TCS */
uint32_t* GetEnclaveEvent(uint64_t tcs);

#endif /* _OE_HOST_ENCLAVE_H */
