// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "enclave_context.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct _ssa_info
{
    void* base_address;
    uint64_t frame_byte_size;
} SSA_Info;

/*
**==============================================================================
**
** oe_read_process_memory()
**
**     This function is used to read process memory.
**
** Parameters:
**     proc - process id.
**     base_addr - A pointer to the base address from which to read.
**     buffer - A pointer to a buffer to receive the process memory content.
**     buffer_size - The number of byte size needed to be read.
**     read_size - A pointer to receive the number of bytes copied to the
**                 buffer.
**
** Returns:
**     0 - success.
**     -1 - failure.
**
**==============================================================================
*/

int oe_read_process_memory(
    pid_t proc,
    void* base_addr,
    void* buffer,
    size_t buffer_size,
    size_t* read_size)
{
    char filename[64];
    int fd = -1;
    int ret = -1;
    ssize_t len = 0;
    off64_t offset = (off64_t)(size_t)base_addr;

    if (base_addr == NULL || buffer == NULL)
    {
        return -1;
    }

    // Open process memory to read.
    snprintf(filename, 64, "/proc/%d/mem", (int)proc);
    fd = open(filename, O_RDONLY | O_LARGEFILE);
    if (fd == -1)
    {
        return -1;
    }

    if (lseek64(fd, offset, SEEK_SET) == -1)
    {
        goto cleanup;
    }

    // Read process memory.
    if ((len = read(fd, buffer, buffer_size)) < 0)
    {
        goto cleanup;
    }

    if (read_size != NULL)
    {
        *read_size = (size_t)len;
    }

    ret = 0;
cleanup:
    close(fd);
    return ret;
}

/*
**==============================================================================
**
** oe_write_process_memory()
**
**     This function is used to write process memory.
**
** Parameters:
**     proc - process id.
**     base_addr - A pointer to the base address from which to written.
**     buffer - - A pointer to a buffer contains the content to be copied.
**     buffer_size - The number of byte size needed to be written.
**     write_size - A pointer to receive the number of bytes copied to the
**                  buffer.
**
** Returns:
**     0 - success.
**     -1 - failure.
**
**==============================================================================
*/

int oe_write_process_memory(
    pid_t proc,
    void* base_addr,
    void* buffer,
    size_t buffer_size,
    size_t* write_size)
{
    char filename[64];
    int fd = -1;
    int ret = -1;
    ssize_t len = 0;
    off64_t offset = (off64_t)(size_t)base_addr;

    if (base_addr == NULL || buffer == NULL)
    {
        return -1;
    }

    // Open process memory to read.
    snprintf(filename, 64, "/proc/%d/mem", (int)proc);
    fd = open(filename, O_RDWR | O_LARGEFILE);
    if (fd == -1)
    {
        return -1;
    }

    if (lseek64(fd, offset, SEEK_SET) == -1)
    {
        goto cleanup;
    }

    // Write process memory.
    if ((len = write(fd, buffer, buffer_size)) < 0)
    {
        goto cleanup;
    }

    if (write_size != NULL)
    {
        *write_size = (size_t)len;
    }

    ret = 0;
cleanup:
    close(fd);
    return ret;
}

static int _get_enclave_ssa_frame_size(
    pid_t pid,
    void* td_t_addr,
    uint64_t* ssa_frame_size)
{
    int ret;
    oe_thread_data_t oe_thread_data;
    size_t read_byte_length = 0;

    oe_sgx_td_t* td = (oe_sgx_td_t*)td_t_addr;
    ret = oe_read_process_memory(
        pid,
        (void*)td,
        (void*)&oe_thread_data,
        sizeof(oe_thread_data_t),
        &read_byte_length);
    if (ret != 0)
    {
        return ret;
    }

    if (read_byte_length != sizeof(oe_thread_data_t))
    {
        return -1;
    }

    *ssa_frame_size = oe_thread_data.__ssa_frame_size;
    if (*ssa_frame_size == 0)
    {
        *ssa_frame_size = OE_DEFAULT_SSA_FRAME_SIZE;
    }

    return 0;
}

static int _get_enclave_thread_current_ssa_info(
    pid_t pid,
    void* tcs_addr,
    SSA_Info* ssa_info)
{
    int ret;
    size_t read_byte_length;
    uint64_t ssa_frame_size = 0;
    sgx_tcs_t tcs;
    void* enclave_base_address;
    void* td_t_addr;

    // Read TCS header.
    ret = oe_read_process_memory(
        pid,
        tcs_addr,
        (void*)&tcs,
        OE_SGX_TCS_HEADER_BYTE_SIZE,
        &read_byte_length);
    if (ret != 0)
    {
        return ret;
    }

    if (read_byte_length != OE_SGX_TCS_HEADER_BYTE_SIZE)
    {
        return -1;
    }

    // SSA is assigned to the page immediately after the tcs page.
    // SSA address is also derived from adding tcs.ossa to enclave base address.
    // See: host/sgx/create.c
    // See:
    // https://github.com/intel/linux-sgx/blob/62b116c502b09b125db9acc965694d3ecff8e698/sdk/debugger_interface/linux/se_ptrace.c#L194-L199
    // This can be used to compute the enclave base address:
    //    encave-base-address + tcs.ossa = tcs_addr + page-size
    //    enclave-base-address = tcs_addr + page-size - tcs.ossa
    enclave_base_address = (uint8_t*)tcs_addr + OE_PAGE_SIZE - tcs.ossa;

    // GS register will point to td_t. GS register value can be computed by
    // adding tcs.gsbase to enclave base address.
    // Note: FS register will also point to td_t upon enclave entry, but
    // enclaves can modify FS register to implement their own threading
    // libraries.
    td_t_addr = (uint8_t*)enclave_base_address + tcs.gsbase;

    // Get SSA frame size
    _get_enclave_ssa_frame_size(pid, td_t_addr, &ssa_frame_size);
    if (ret != 0)
    {
        return ret;
    }

    // Get current SSA base addr and size.
    ssa_info->base_address =
        (void*)(((uint8_t*)tcs_addr) + OE_SSA_FROM_TCS_BYTE_OFFSET + (tcs.cssa - 1) * ssa_frame_size * OE_PAGE_SIZE);
    ssa_info->frame_byte_size = ssa_frame_size * OE_PAGE_SIZE;
    return 0;
}

static inline void _ssa_gpr_to_user_regs(
    const sgx_ssa_gpr_t* ssa_gpr,
    struct user_regs_struct* regs)
{
    regs->rax = ssa_gpr->rax;
    regs->rbx = ssa_gpr->rbx;
    regs->rcx = ssa_gpr->rcx;
    regs->rdx = ssa_gpr->rdx;

    regs->rdi = ssa_gpr->rdi;
    regs->rsi = ssa_gpr->rsi;

    regs->rbp = ssa_gpr->rbp;
    regs->rsp = ssa_gpr->rsp;

    regs->r8 = ssa_gpr->r8;
    regs->r9 = ssa_gpr->r9;
    regs->r10 = ssa_gpr->r10;
    regs->r11 = ssa_gpr->r11;
    regs->r12 = ssa_gpr->r12;
    regs->r13 = ssa_gpr->r13;
    regs->r14 = ssa_gpr->r14;
    regs->r15 = ssa_gpr->r15;

    regs->rip = ssa_gpr->rip;
    regs->eflags = ssa_gpr->rflags;
    return;
}

static inline void _user_regs_to_ssa_gpr(
    const struct user_regs_struct* regs,
    sgx_ssa_gpr_t* ssa_gpr)
{
    ssa_gpr->rax = regs->rax;
    ssa_gpr->rbx = regs->rbx;
    ssa_gpr->rcx = regs->rcx;
    ssa_gpr->rdx = regs->rdx;

    ssa_gpr->rdi = regs->rdi;
    ssa_gpr->rsi = regs->rsi;

    ssa_gpr->rbp = regs->rbp;
    ssa_gpr->rsp = regs->rsp;

    ssa_gpr->r8 = regs->r8;
    ssa_gpr->r9 = regs->r9;
    ssa_gpr->r10 = regs->r10;
    ssa_gpr->r11 = regs->r11;
    ssa_gpr->r12 = regs->r12;
    ssa_gpr->r13 = regs->r13;
    ssa_gpr->r14 = regs->r14;
    ssa_gpr->r15 = regs->r15;

    ssa_gpr->rip = regs->rip;
    ssa_gpr->rflags = regs->eflags;
    return;
}

/*
**==============================================================================
**
** oe_get_enclave_thread_gpr()
**
**     This function is used get the GPR registers of the enclave thread.
**
** Parameters:
**     pid - The process id.
**     tcs_addr - The enclave thread tcs address.
**     regs - A pointer to receive the output GPR.
**
** Returns:
**     0 - Success.
**     Non zero error code - Failure.
**
**==============================================================================
*/

int oe_get_enclave_thread_gpr(
    pid_t pid,
    void* tcs_addr,
    struct user_regs_struct* regs)
{
    int ret;
    size_t read_byte_length;
    SSA_Info ssa_info;
    sgx_ssa_gpr_t ssa_gpr;
    void* gpr_addr;

    // Get current ssa info.
    ret = _get_enclave_thread_current_ssa_info(pid, tcs_addr, &ssa_info);
    if (ret != 0)
    {
        return ret;
    }

    // Get gpr base address. Gpr is at the end of an SSA frame.
    gpr_addr =
        (void*)(((uint8_t*)ssa_info.base_address) + ssa_info.frame_byte_size - OE_SGX_GPR_BYTE_SIZE);

    // Read gpr from ssa.
    ret = oe_read_process_memory(
        pid,
        gpr_addr,
        (void*)&ssa_gpr,
        sizeof(sgx_ssa_gpr_t),
        &read_byte_length);
    if (ret != 0)
    {
        return ret;
    }

    if (read_byte_length != sizeof(sgx_ssa_gpr_t))
    {
        return -1;
    }

    // Fill in user_regs_struct.
    _ssa_gpr_to_user_regs(&ssa_gpr, regs);

    return 0;
}

/*
**==============================================================================
**
** oe_set_enclave_thread_gpr()
**
**     This function is used get the GPR registers of the enclave thread.
**
** Parameters:
**     pid - The process id.
**     tcs_addr - The enclave thread tcs address.
**     regs - A pointer to input GPR.
**
** Returns:
**     0 - Success.
**     Non zero error code - Failure.
**
**==============================================================================
*/

int oe_set_enclave_thread_gpr(
    pid_t pid,
    void* tcs_addr,
    struct user_regs_struct* regs)
{
    int ret;
    size_t read_byte_length;
    size_t write_byte_length;
    SSA_Info ssa_info;
    sgx_ssa_gpr_t ssa_gpr;
    void* gpr_addr;

    // Get current ssa frame info.
    ret = _get_enclave_thread_current_ssa_info(pid, tcs_addr, &ssa_info);
    if (ret != 0)
    {
        return ret;
    }

    // Get gpr base address. Gpr is at the end of an SSA frame.
    gpr_addr =
        (void*)(((uint8_t*)ssa_info.base_address) + ssa_info.frame_byte_size - OE_SGX_GPR_BYTE_SIZE);

    // Read gpr from ssa.
    ret = oe_read_process_memory(
        pid,
        gpr_addr,
        (void*)&ssa_gpr,
        sizeof(sgx_ssa_gpr_t),
        &read_byte_length);
    if (ret != 0)
    {
        return ret;
    }

    if (read_byte_length != sizeof(sgx_ssa_gpr_t))
    {
        return -1;
    }

    // Write the general registers to ssa gpr structure.
    _user_regs_to_ssa_gpr(regs, &ssa_gpr);

    // Write gpr value to ssa.
    ret = oe_write_process_memory(
        pid,
        gpr_addr,
        (void*)&ssa_gpr,
        sizeof(sgx_ssa_gpr_t),
        &write_byte_length);
    if (ret != 0)
    {
        return ret;
    }

    if (write_byte_length != sizeof(sgx_ssa_gpr_t))
    {
        return -1;
    }

    return ret;
}

/*
**==============================================================================
**
** oe_get_enclave_thread_fpr()
**
**     This function is used get the FPR registers of the enclave thread.
**
** Parameters:
**     pid - The process id.
**     tcs_addr - The enclave thread tcs address.
**     regs - A pointer to receive the output FPR.
**
** Returns:
**     0 - Success.
**     Non zero error code - Failure.
**
**==============================================================================
*/

int oe_get_enclave_thread_fpr(
    pid_t pid,
    void* tcs_addr,
    struct user_fpregs_struct* regs)
{
    int ret;
    size_t read_byte_length;
    SSA_Info ssa_info;

    // Get current ssa frame info.
    ret = _get_enclave_thread_current_ssa_info(pid, tcs_addr, &ssa_info);
    if (ret != 0)
    {
        return ret;
    }

    // Read fpr values from ssa.
    ret = oe_read_process_memory(
        pid,
        ssa_info.base_address,
        (void*)regs,
        sizeof(struct user_fpregs_struct),
        &read_byte_length);
    if (ret != 0)
    {
        return ret;
    }

    if (read_byte_length != sizeof(struct user_fpregs_struct))
    {
        return -1;
    }

    return 0;
}

/*
**==============================================================================
**
** oe_set_enclave_thread_fpr()
**
**     This function is used get the FPR registers of the enclave thread.
**
** Parameters:
**     pid - The process id.
**     tcs_addr - The enclave thread tcs address.
**     regs - A pointer to the input FPR.
**
** Returns:
**     0 - Success.
**     Non zero error code - Failure.
**
**==============================================================================
*/

int oe_set_enclave_thread_fpr(
    pid_t pid,
    void* tcs_addr,
    struct user_fpregs_struct* regs)
{
    int ret;
    size_t write_byte_length;
    SSA_Info ssa_info;

    // Get current ssa frame info.
    ret = _get_enclave_thread_current_ssa_info(pid, tcs_addr, &ssa_info);
    if (ret != 0)
    {
        return ret;
    }

    // Write fpr values to ssa.
    ret = oe_write_process_memory(
        pid,
        ssa_info.base_address,
        (void*)regs,
        sizeof(struct user_fpregs_struct),
        &write_byte_length);
    if (ret != 0)
    {
        return ret;
    }

    if (write_byte_length != sizeof(struct user_fpregs_struct))
    {
        return -1;
    }

    return ret;
}

/*
**==============================================================================
**
** oe_get_enclave_thread_xstate()
**
**     This function is used get the XState of the enclave thread.
**
** Parameters:
**     pid - The process id.
**     tcs_addr - The enclave thread tcs address.
**     xstate - A pointer to a buffer to receive the xstate content.
**     xstate_size - The number of byte size of the xstate buffer.
**
** Returns:
**     0 - Success.
**     Non zero error code - Failure.
**
**==============================================================================
*/

int oe_get_enclave_thread_xstate(
    pid_t pid,
    void* tcs_addr,
    void* xstate,
    uint64_t xstate_size)
{
    int ret;
    size_t read_byte_length;
    SSA_Info ssa_info;

    // Get current ssa frame info.
    ret = _get_enclave_thread_current_ssa_info(pid, tcs_addr, &ssa_info);
    if (ret != 0)
    {
        return ret;
    }

    if (xstate_size >
        (ssa_info.frame_byte_size - sizeof(struct user_regs_struct)))
    {
        return -1;
    }

    // Read xstate from ssa.
    ret = oe_read_process_memory(
        pid,
        ssa_info.base_address,
        (void*)xstate,
        xstate_size,
        &read_byte_length);
    if (ret != 0)
    {
        return ret;
    }

    if (read_byte_length != xstate_size)
    {
        return -1;
    }

    return 0;
}

/*
**==============================================================================
**
** oe_set_enclave_thread_xstate()
**
**     This function is used set the XState of the enclave thread.
**
** Parameters:
**     pid - The process id.
**     tcs_addr - The enclave thread tcs address.
**     xstate - A pointer to a buffer contains the xstate content.
**     xstate_size - The number of byte size of the xstate buffer.
**
** Returns:
**     0 - Success.
**     Non zero error code - Failure.
**
**==============================================================================
*/

int oe_set_enclave_thread_xstate(
    pid_t pid,
    void* tcs_addr,
    void* xstate,
    uint64_t xstate_size)
{
    int ret;
    size_t write_byte_length;
    SSA_Info ssa_info;

    // Get current ssa frame info.
    ret = _get_enclave_thread_current_ssa_info(pid, tcs_addr, &ssa_info);
    if (ret != 0)
    {
        return ret;
    }

    if (xstate_size >
        (ssa_info.frame_byte_size - sizeof(struct user_regs_struct)))
    {
        return -1;
    }

    // Write xstate values to ssa.
    ret = oe_write_process_memory(
        pid,
        ssa_info.base_address,
        (void*)xstate,
        xstate_size,
        &write_byte_length);
    if (ret != 0)
    {
        return ret;
    }

    if (write_byte_length != xstate_size)
    {
        return -1;
    }

    return ret;
}

/*
**==============================================================================
**
** oe_is_aep()
**
**     This function is used to check if the input thread is on a OE AEP.
**
** Parameters:
**     pid - The process id.
**     regs - The pointer to the GPR registers.
**
** Returns:
**     true - If the current pc is an OE AEP.
**     false - If the current pc is not an OE AEP.
**
**==============================================================================
*/

bool oe_is_aep(pid_t pid, struct user_regs_struct* regs)
{
    uint32_t op_code;

    // Check if rax matches with ENCLU_ERESUME leaf.
    if (regs->rax != ENCLU_ERESUME)
    {
        return false;
    }

    if (oe_read_process_memory(
            pid, (void*)regs->rip, (char*)&op_code, sizeof(op_code), NULL) != 0)
    {
        return false;
    }

    // Check the op_code matches with ENCLU.
    if ((op_code & 0xffffff) == ENCLU_INSTRUCTION)
    {
        return true;
    }

    return false;
}
