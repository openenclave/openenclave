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
#include "ocalls.h"

#if 0
#define TRACE 1
#endif

#ifdef TRACE
# define D(EXPR) EXPR
#else
# define D(EXPR)
#endif

/*
**==============================================================================
**
** _SetThreadData()
**
**     Set the thread data for the current thread using thread-specific data.
**
**==============================================================================
*/

static OE_OnceType _once;
static OE_ThreadKey _key;

static void _SetTDInit()
{
    OE_ThreadKeyCreate(&_key, NULL);
}

static void _SetThreadData(ThreadData* td)
{
    OE_Once(&_once, _SetTDInit);
    OE_ThreadSetSpecific(_key, td);
}

/*
**==============================================================================
**
** GetThreadData()
**
**     Get the ThreadData for the current thread from thread-specific data.
**
**==============================================================================
*/

ThreadData* GetThreadData()
{
    OE_Once(&_once, _SetTDInit);
    return (ThreadData*)OE_ThreadGetSpecific(_key);
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

#if 0
    /* Get address of enclave's OE_Main() function */
    if (enclave->handle)
    {
        tcs->u.main = (void (*)(void))dlsym(enclave->handle, "OE_Main");
    }
    else
#endif
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
**     Caution: this function must always be inline because the calling
**     function makes assumptions about the layout of the stack related
**     to outside stack allocation performed by the enclave.
**
**==============================================================================
*/

__attribute__((always_inline))
static OE_Result _DoEENTER(
    OE_Enclave* enclave,
    void* tcs,
    void (*aep)(void), 
    OE_Code codeIn,
    int funcIn,
    uint64_t argIn,
    OE_Code* codeOut,
    int* funcOut,
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
    printf("_DoEENTER(tcs=%p aep=%p codeIn=%d, funcIn=%x argIn=%p)\n",
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
        *funcOut = (int)OE_LO_WORD(arg3);
        *argOut = arg4;
    }

    result = OE_OK;

catch:
    return result;
}

/*
**==============================================================================
**
** _HandleAsyncException()
**
**     Handle an Asynchronous EXception resulting from an enclave fault.
**
**==============================================================================
*/

static void _HandleAsyncException(void)
{
    unsigned long rdx = 0x00;
    ThreadData* td;

#if (TRACE == 2)
    printf("=== _HandleAsyncException()\n");
#endif

    /* Get the ThreadData from thread-specific data */
    td = GetThreadData();
    assert(td);

    asm("movl %0, %%eax\n\t"
        "movq %1, %%rbx\n\t"
        "movq %2, %%rcx\n\t"
        "movq %3, %%rdx\n\t"
        ".byte 0x0F\n\t"
        ".byte 0x01\n\t"
        ".byte 0xd7\n\t"
        :
        :
        "a"((uint32_t)ENCLU_ERESUME),
        "b"(td->tcs),
        "c"(_HandleAsyncException),
        "d"(rdx));
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
** _HandleOCALL()
**
**     Handle calls from the enclave (OCALL)
**
**==============================================================================
*/

static OE_Result _HandleOCALL(
    OE_Enclave* enclave,
    void* tcs,
    int func,
    uint64_t argIn,
    uint64_t* argOut)
{
    OE_Result result = OE_UNEXPECTED;

    if (!enclave || !tcs || !func)
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

        default:
            abort();
    }

    result = OE_OK;

catch:
    return result;
}

/*
**==============================================================================
**
** _AssignTCS()
**
**     Return a pointer to the first available ThreadData (or first ThreadData already
**     assigned to this thread).
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
** __OE_ECall()
**
**     This function initiates and ECALL.
**
**==============================================================================
*/

__attribute__((cdecl))
OE_Result __OE_ECall(
    OE_Enclave* enclave,
    int func,
    uint64_t arg,
    uint64_t* argOut_)
{
    OE_Result result = OE_UNEXPECTED;
    void* tcs = NULL;
    OE_Code code = OE_CODE_ECALL;
    OE_Code codeOut = 0;
    int funcOut = 0;
    uint64_t argOut = 0;

    if (!enclave)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Assign a TD for this operation */
    if (!(tcs = _AssignTCS(enclave)))
        OE_THROW(OE_OUT_OF_THREADS);

    D( printf("=== OE_ECall(tcs=%p)\n", tcs); )

eenter:

    if (code == OE_CODE_ECALL)
    {
        D( printf("--> ECALL(func=%x)\n", func); )
    }
    else if (code == OE_CODE_ORET)
    {
        D( printf("--> ORET(func=%x)\n", func); )
    }

    /* Perform ECALL or ORET */
    OE_TRY(_DoEENTER(
        enclave,
        tcs, 
        _HandleAsyncException, 
        code,
        func, 
        arg, 
        &codeOut,
        &funcOut, 
        &argOut));

    /* Process OCALLS */
    if (codeOut == OE_CODE_OCALL)
    {
        D( printf("<-- OCALL(func=%x)\n", funcOut); )

        /* Handle the OCALL */
        func = funcOut;
        arg = argOut;
        argOut = 0;
        OE_TRY(_HandleOCALL(enclave, tcs, func, arg, &argOut));

        /* Perform the ORET */
        code = OE_CODE_ORET;
        arg = argOut;
        argOut = 0;
        goto eenter;
    }
    else if (codeOut == OE_CODE_ERET)
    {
        D( printf("<-- ERET()\n") );

        if (argOut)
            *argOut_ = argOut;
    }
    else
    {
        D( printf("Bad code: %u\n", codeOut) );
        OE_THROW(OE_UNEXPECTED);
    }

    result = OE_OK;

catch:

    if (enclave && tcs)
        _ReleaseTCS(enclave, tcs);

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
        return NULL;

    for (i = 0; i < enclave->num_ecalls; i++)
    {
        if (strcmp(enclave->ecalls[i].name, func) == 0)
        {
            *index = i;
            return enclave->ecalls[i].vaddr;
        }
    }

    /* Not found! */
    return NULL;
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
        SetEnclave(enclave);

        uint64_t argOut = 0;

        OE_TRY(__OE_ECall(
            enclave, 
            OE_FUNC_CALL_ENCLAVE, 
            (uint64_t)&callEnclaveArgs, 
            &argOut));

        SetEnclave(NULL);
    }

    /* Check the result */
    OE_TRY(callEnclaveArgs.result);

    result = OE_OK;

catch:
    return result;
}
