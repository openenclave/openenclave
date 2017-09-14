#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <dlfcn.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include "asmdefs.h"
#include "enclave.h"
#include <openenclave/host.h>
#include <openenclave/bits/utils.h>
#include <openenclave/bits/build.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/registers.h>
#include <openenclave/bits/registers.h>
#include "ocalls.h"

#define TRACE 0

#if 0
# define D(X) X
#else
# define D(X)
#endif

void OE_AEP(void);

/*
**==============================================================================
**
** _SetThreadData()
**
**     Store the thread data in the GS segement register. Note that the GS
**     register is unused on X86-64, unlike the FS register that is used by
**     the pthread implementation.
**
**     The OE_AEP() function (aep.S) uses the GS segment register to retrieve
**     the ThreadData.tcs field.
**
**==============================================================================
*/

static void _SetThreadData(ThreadData* td)
{
    if (OE_SetGSRegisterBase(td) != 0)
    {
        assert(0);
    }
}

/*
**==============================================================================
**
** GetThreadData()
**
**     Retrieve the a pointer to the ThreadData from the GS segment register.
**
**==============================================================================
*/

ThreadData* GetThreadData()
{
    const void* ptr;

    if (OE_GetGSRegisterBase(&ptr) != 0)
    {
        assert(0);
    }

    return (ThreadData*)ptr;
}

/*
**==============================================================================
**
** _EnterSim()
**
**     Simulated version of OE_Enter()
**
**==============================================================================
*/

static OE_Result _EnterSim(
    OE_Enclave* enclave,
    void* tcs_,
    void (*aep)(),
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4)
{
    OE_Result result = OE_UNEXPECTED;
    SGX_TCS* tcs = (SGX_TCS*)tcs_;
    const void* saved_gsbase = NULL;

    /* Reject null parameters */
    if (!enclave || !enclave->addr || !tcs || !tcs->oentry || !tcs->gsbase)
        OE_THROW(OE_INVALID_PARAMETER);

    tcs->u.main = (void (*)(void))(enclave->addr + tcs->oentry);

    if (!tcs->u.main)
        OE_THROW(OE_NOT_FOUND);

    /* Save old GS register base, and set new one */
    {
        const void* gsbase = (void*)(enclave->addr + tcs->gsbase);

        if (OE_GetGSRegisterBase(&saved_gsbase) != 0)
            OE_THROW(OE_FAILURE);

        if (OE_SetGSRegisterBase(gsbase) != 0)
            OE_THROW(OE_FAILURE);

        /* Set TD.simulate flag */
        {
            TD* td = (TD*)gsbase;
            td->simulate = true;
        }
    }

    /* Call into enclave */
    {
        OE_EnterSim(tcs, aep, arg1, arg2, arg3, arg4);

        /* Restore the GS segment register */
        if (OE_SetGSRegisterBase(saved_gsbase) != 0)
            OE_THROW(OE_FAILURE);
    }

    result = OE_OK;

catch:

    return result;
}

/*
**==============================================================================
**
** _DoEENTER()
**
**     Execute the EENTER instruction with the given parameters.
**
**==============================================================================
*/

__attribute__((always_inline))
static OE_Result _DoEENTER(
    OE_Enclave* enclave,
    void* tcs,
    void (*aep)(void), 
    OE_Code codeIn,
    uint32_t funcIn,
    uint64_t argIn,
    OE_Code* codeOut,
    uint32_t* funcOut,
    uint64_t* argOut)
{
    OE_Result result = OE_UNEXPECTED;

    if (codeOut)
        *codeOut = OE_CODE_NONE;

    if (funcOut)
        *funcOut = 0;

    if (argOut)
        *argOut = 0;

    if (!codeOut || !funcOut || !argOut)
        OE_THROW(OE_INVALID_PARAMETER);

#if (TRACE == 2)
    printf("_DoEENTER(tcs=%p aep=%p codeIn=%d, funcIn=%x argIn=%lx)\n",
        tcs, aep, codeIn, funcIn, argIn);
#endif

    /* Call OE_Enter() assembly function (enter.S) */
    {
        uint64_t arg1 = OE_MAKE_WORD(codeIn, funcIn);
        uint64_t arg2 = (uint64_t)argIn;
        uint64_t arg3;
        uint64_t arg4;

        if (enclave->simulate)
        {
            OE_TRY(_EnterSim(enclave, tcs, aep, arg1, arg2, &arg3, &arg4));
        }
        else
        {
            OE_Enter(tcs, aep, arg1, arg2, &arg3, &arg4);
        }

        *codeOut = (OE_Code)OE_HI_WORD(arg3);
        *funcOut = OE_LO_WORD(arg3);
        *argOut = arg4;
    }

    result = OE_OK;

catch:
    return result;
}

/*
**==============================================================================
**
** _FindHostFunc()
**
**     Find the function in the host with the given name.
**
**==============================================================================
*/

static OE_HostFunc _FindHostFunc(
    const char* name)
{
    void* handle = dlopen(NULL, RTLD_NOW | RTLD_GLOBAL);
    OE_HostFunc func;

    if (!handle)
        return NULL;

    func = (OE_HostFunc)dlsym(handle, name);
    dlclose(handle);

    return func;
}

/*
**==============================================================================
**
** _HandleCallHost()
**
**     Handle calls from the enclave
**
**==============================================================================
*/

static void _HandleCallHost(uint64_t arg)
{
    OE_CallHostArgs* args = (OE_CallHostArgs*)arg;
    OE_HostFunc func;

    if (!args)
        return;

    if (!args->func)
    {
        args->result = OE_INVALID_PARAMETER;
        return;
    }

    args->result = OE_UNEXPECTED;

    /* Find the host function with this name */
    if (!(func = _FindHostFunc(args->func)))
    {
        args->result = OE_NOT_FOUND;
        return;
    }

    /* Invoke the function */
    func(args->args);

    args->result = OE_OK;
}

/*
**==============================================================================
**
** OE_RegisterOCall()
**
**     Register the given OCALL function, associate it with the given function
**     number.
**
**==============================================================================
*/

static OE_OCallFunction _ocalls[OE_MAX_OCALLS];
static OE_Spinlock _ocalls_spinlock = OE_SPINLOCK_INITIALIZER;

OE_Result OE_RegisterOCall(
    uint32_t func,
    OE_OCallFunction ocall)
{
    OE_Result result = OE_UNEXPECTED;
    OE_SpinLock(&_ocalls_spinlock);

    if (func >= OE_MAX_OCALLS)
        OE_THROW(OE_OUT_OF_RANGE);

    if (_ocalls[func])
        OE_THROW(OE_ALREADY_IN_USE);

    _ocalls[func] = ocall;

    result = OE_OK;

catch:
    OE_SpinUnlock(&_ocalls_spinlock);
    return result;
}

/*
**==============================================================================
**
** _HandleOCALL()
**
**     Handle calls from the enclave (OCALL)
**
**==============================================================================
*/

static OE_Result _HandleOCALL(
    OE_Enclave* enclave,
    void* tcs,
    uint32_t func,
    uint64_t argIn,
    uint64_t* argOut)
{
    OE_Result result = OE_UNEXPECTED;

    if (!enclave || !tcs)
        OE_THROW(OE_INVALID_PARAMETER);

    if (argOut)
        *argOut = 0;

    switch ((OE_Func)func)
    {
        case OE_FUNC_CALL_HOST:
            _HandleCallHost(argIn);
            break;

        case OE_FUNC_MALLOC:
            HandleMalloc(argIn, argOut);
            break;

        case OE_FUNC_FREE:
            HandleFree(argIn);
            break;

        case OE_FUNC_PUTS:
            HandlePuts(argIn);
            break;

        case OE_FUNC_PRINT:
            HandlePrint(argIn);
            break;

        case OE_FUNC_PUTCHAR:
            HandlePutchar(argIn);
            break;

        case OE_FUNC_THREAD_WAIT:
            HandleThreadWait(argIn);
            break;

        case OE_FUNC_THREAD_WAKE:
            HandleThreadWake(argIn);
            break;

        case OE_FUNC_THREAD_WAKE_WAIT:
            HandleThreadWakeWait(argIn);
            break;

        case OE_FUNC_INIT_QUOTE:
            HandleInitQuote(argIn);
            break;

        case OE_FUNC_STRFTIME:
            HandleStrftime(argIn);
            break;

        case OE_FUNC_GETTIMEOFDAY:
            HandleGettimeofday(argIn);
            break;

        case OE_FUNC_CLOCK_GETTIME:
            HandleClockgettime(argIn);
            break;

        case OE_FUNC_NANOSLEEP:
            HandleNanosleep(argIn);
            break;

        case OE_FUNC_DESTRUCTOR:
        case OE_FUNC_CALL_ENCLAVE:
            assert("Invalid OCALL" == NULL);
            break;

        default:
        {
            /* Dispatch user-registered OCALLs */
            if (func < OE_MAX_OCALLS)
            {
                OE_SpinLock(&_ocalls_spinlock);
                OE_OCallFunction ocall = _ocalls[func];
                OE_SpinUnlock(&_ocalls_spinlock);

                if (ocall)
                    ocall(argIn, argOut);
            }

            break;
        }
    }

    result = OE_OK;

catch:
    return result;
}

/*
**==============================================================================
**
** __OE_DispatchOCall()
**
**     This function is called by OE_Enter() (see enter.S). It checks to
**     to see if EENTER returned in order to perform an OCALL. If so it 
**     dispatches the OCALL.
**
** Parameters:
**     arg1 - first argument from EENTER return (code + func)
**     arg2 - second argument from EENTER return (OCALL argument)
**     arg1Out - first argument to pass to EENTER (code + func)
**     arg2Out - second argument to pass to EENTER (ORET argument)
**
** Returns:
**     0 - An OCALL was dispatched
**     1 - No OCALL was dispatched
**
**==============================================================================
*/

int __OE_DispatchOCall(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg1Out,
    uint64_t* arg2Out,
    void* tcs,
    void* rsp)
{
    const OE_Code code = (OE_Code)OE_HI_WORD(arg1);
    const uint32_t func = (OE_Code)OE_LO_WORD(arg1);
    const uint64_t arg = arg2;

    if (code == OE_CODE_OCALL)
    {
        OE_Enclave* enclave = GetEnclave();
        // ATTN: this asserts with call nesting!
        // Pass enclave as argument to _DoEnter()
        assert(enclave != NULL);

        uint64_t argOut = 0;

        OE_Result result = _HandleOCALL(enclave, tcs, func, arg, &argOut);

        /* ATTN: ignored! */
        (void)result;

        *arg1Out = OE_MAKE_WORD(OE_CODE_ORET, func);
        *arg2Out = argOut;

        return 0;
    }

    /* Not an OCALL */
    return 1;
}

/*
**==============================================================================
**
** _AssignTCS()
**
**     Return a pointer to the first available ThreadData (or first ThreadData 
**     already assigned to this thread).
**
**==============================================================================
*/

static void* _AssignTCS(
    OE_Enclave* enclave)
{
    void* tcs = NULL;
    size_t i;
    OE_Thread thread = OE_ThreadSelf();

    OE_SpinLock(&enclave->lock);
    {
        /* First attempt to find a busy TD owned by this thread */
        for (i = 0; i < enclave->num_tds; i++)
        {
            ThreadData* td = &enclave->tds[i];

            if (td->busy && td->thread == thread)
            {
                td->count++;
                tcs = (void*)td->tcs;
                break;
            }
        }

        /* If ThreadData not found yet, look for an available ThreadData */
        if (!tcs)
        {
            for (i = 0; i < enclave->num_tds; i++)
            {
                ThreadData* td = &enclave->tds[i];

                if (!td->busy)
                {
                    td->busy = true;
                    td->thread = thread;
                    td->count = 1;
                    tcs = (void*)td->tcs;

                    /* Set into TSD so _HandleAsyncException can get it */
                    _SetThreadData(td);
                    assert(GetThreadData() == td);
                    break;
                }
            }
        }
    }
    OE_SpinUnlock(&enclave->lock);

    /* Inject TCS into pthread data (beyond portion used by system) */
    asm volatile(
        "mov %0, %%rax\n\t"
        "mov %%rax, %%fs:2048\n\t"
        :
        :
        "m"(tcs));

    return tcs;
}

/*
**==============================================================================
**
** _ReleaseTCS()
**
**     Release a ThreadData or just decrement if it has been assigned
**     to the same element more than once.
**
**==============================================================================
*/

static void _ReleaseTCS(
    OE_Enclave* enclave,
    void* tcs)
{
    size_t i;

    OE_SpinLock(&enclave->lock);
    {
        for (i = 0; i < enclave->num_tds; i++)
        {
            ThreadData* td = &enclave->tds[i];

            if (td->busy && (void*)td->tcs == tcs)
            {
                td->count--;

                if (td->count == 0)
                {
                    td->busy = false;
                    td->thread = 0;
                    td->event = 0;
                    _SetThreadData(NULL);
                    assert(GetThreadData() == NULL);
                }
                break;
            }
        }
    }
    OE_SpinUnlock(&enclave->lock);
}

/*
**==============================================================================
**
** OE_ECall()
**
**     This function initiates and ECALL.
**
**==============================================================================
*/

__attribute__((cdecl))
OE_Result OE_ECall(
    OE_Enclave* enclave,
    uint32_t func,
    uint64_t arg,
    uint64_t* argOut_)
{
    OE_Result result = OE_UNEXPECTED;
    void* tcs = NULL;
    OE_Code code = OE_CODE_ECALL;
    OE_Code codeOut = 0;
    uint32_t funcOut = 0;
    uint64_t argOut = 0;

    if (!enclave)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Set into thread local storage so it can be retrieved during an OCALL */
    SetEnclave(enclave);

    /* Assign a TD for this operation */
    if (!(tcs = _AssignTCS(enclave)))
        OE_THROW(OE_OUT_OF_THREADS);

    /* Perform ECALL or ORET */
    OE_TRY(_DoEENTER(
        enclave,
        tcs, 
        OE_AEP, 
        code,
        func, 
        arg, 
        &codeOut,
        &funcOut, 
        &argOut));

    /* Process OCALLS */
    if (codeOut != OE_CODE_ERET)
        OE_THROW(OE_UNEXPECTED);

    if (argOut)
        *argOut_ = argOut;

    result = OE_OK;

catch:

    if (enclave && tcs)
        _ReleaseTCS(enclave, tcs);

    // ATTN: this causes an assertion with call nesting.
    // ATTN: make enclave argument a cookie.
    // SetEnclave(NULL);

    return result;
}

/*
**==============================================================================
**
** _FindEnclaveFunc()
**
**     Find the enclave function with the given name
**
**==============================================================================
*/

static uint64_t _FindEnclaveFunc(
    OE_Enclave* enclave,
    const char* func,
    uint64_t* index)
{
    size_t i;

    if (index)
        *index = 0;

    if (!enclave || !func || !index)
        return 0;

    for (i = 0; i < enclave->num_ecalls; i++)
    {
        if (strcmp(enclave->ecalls[i].name, func) == 0)
        {
            *index = i;
            return enclave->ecalls[i].vaddr;
        }
    }

    /* Not found! */
    return 0;
}

/*
**==============================================================================
**
** OE_CallEnclave()
**
**     Call the named function in the enclave.
**
**==============================================================================
*/

OE_Result OE_CallEnclave(
    OE_Enclave* enclave,
    const char* func,
    void* args)
{
    OE_Result result = OE_UNEXPECTED;
    OE_CallEnclaveArgs callEnclaveArgs;

    /* Reject invalid parameters */
    if (!enclave || !func)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize the callEnclaveArgs structure */
    {
        if (!(callEnclaveArgs.vaddr = _FindEnclaveFunc(
            enclave, func, &callEnclaveArgs.func)))
        {
            OE_THROW(OE_NOT_FOUND);
        }

        callEnclaveArgs.args = args;
        callEnclaveArgs.result = OE_UNEXPECTED;
    }

    /* Peform the ECALL */
    {
        uint64_t argOut = 0;

        OE_TRY(OE_ECall(
            enclave, 
            OE_FUNC_CALL_ENCLAVE, 
            (uint64_t)&callEnclaveArgs, 
            &argOut));
    }

    /* Check the result */
    OE_TRY(callEnclaveArgs.result);

    result = OE_OK;

catch:
    return result;
}
