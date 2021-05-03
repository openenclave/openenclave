SGX Enclave Memory Manager
=================================

## Motivation ##

An enclave's memory is backed by a special reserved region in RAM, called Enclave Page Cache (EPC). Enclave memory management tasks include allocating/reserving virtual address ranges, committing physical EPC pages, changing EPC page permissions or page type, and removing EPC pages. Those tasks require collaboration between the trusted runtime, the untrusted runtime, and the OS. The SGX enclave memory manager (EMM) serves as a central component in the enclave trusted runtime that abstracts the interaction with the untrusted runtime for all memory management flows and provides APIs for its clients to reserve virtual address ranges, commit EPC memory to the reserved address ranges, and modify attributes of the reserved/committed pages.   

For details of specific memory management related flows, please refer to [the SGX EDMM driver API spec](https://github.com/openenclave/openenclave/pull/3755/files). The public EMM APIs defined here are most likely invoked by some intermediate runtime level components for specific usages, such as dynamic heap/stack, mmap, mprotect, higher level language JIT compiler, etc.   

## User Experience ##

**Allocate, Deallocate Enclave Memory**

The EMM provides an API, sgx_mm_alloc, for clients to request enclave memory allocations. An enclave memory allocation represents both a reserved virtual address range and a commitment of EPC pages.  EPC pages are committed for enclaves via special SGX instructions: loaded by EADD/EEXTEND before EINIT or dynamically added using EAUG followed by EACCEPT. 

The sgx_mm_alloc API allows clients to specify one of three committing modes for an allocation: 
- EMA_RESERVE, only the virtual address range is reserved. No EPC pages will be committed in this mode.  
- EMA_COMMIT_NOW: reserves and commits physical EPC committed upon allocation. EACCEPT will be done immediately.
- EMA_COMMIT_ON_DEMAND: EACCEPT is done on demand, see below on committing and uncommitting.

An allocation, once created, will own its address range until the deallocation API, sgx_mm_dealloc, is called upon. No two active allocations can have overlapping address ranges.

**Commit, Uncommit Enclave Memory**

When a page in COMMIT_ON_DEMAND allocations is accessed, a page fault occurs if the page was not yet commited.  The EMM will perform EACCEPT to commit the EPC page on page fault after OS doing EAUG. 

The clients can also call the EMM commit API, sgx_mm_commit, to proactively commit specific sub-regions in a COMMIT_ON_DEMAND allocation to avoid future page fault.

Some EMM clients, <i>e.g.</i>, a dynamic code loader wishing to load code on page faults, can register a custom handler for page faults at the time of allocation request. In the custom page fault handler, it can invoke an API, sgx_mm_commit_data, to commit and load data to newly committed EPC page at the same time as supported by EACCEPTCOPY. 

Committed pages will stay committed (regardless how they were committed) until the clients calls the uncommit API, sgx_mm_uncommit, on them or the allocation they belong to is deallocated by sgx_mm_dealloc.    

**Modify Page Attributes**

The EMM clients may call sgx_mm_modify/sgx_mm_modify_ex to request permissions and/or page type changes for pages in existing allocations.


## Notes on Internal Design ##

The enclave memory manager keeps track of memory allocation and layout info inside enclave address range (ELRANGE) using an internal structure called the Enclave Memory Area (EMA) List. The EMA and EMA list are considered private data structure of memory manager, and their internals are not exposed in client-facing APIs.
- The EMA list tracks all memory regions in use (reserved, committed, commit-on-demand) in ELRANGE.
- Ranges in ELRANGE not tracked by an EMA are considered free and ready for new allocations
- The EMM labels certain EMAs reserved for runtime or its internal usage and make them not accessible from public APIs.
- A thread calling an EMM API on an EMA with operation pending in another thread will wait until the pending operation is finished. 

**Assumptions:**

- When enclave is loaded, the OS has reserved the whole address range covered by ELRANGE. It is assumed the host app will not remap any part of this reserved range.
  - In the future, when the new feature that allows loading an enclave with base address at zero, we may support partial ELRANGE reserved by the OS.  
- Memory manager does not check EPC pressure, or proactively trim pages when EPC runs low. The OS can reclaim EPC pages when EPC running low or cgroups threshold reached
- Memory manager does not maintain and recycle committed then freed pages
  - Whenever a page is freed (via dealloc or uncommit API), it is trimmed from enclave and need be re-allocated and committed before re-use.
  - Owner of a region can re-purpose a sub-region of it by calling sgx_mm_modify_type/permissions to split out the sub-region to be reused.
- Memory manager does not call back client for #GP handling. Memory manager code will ensure itself would not cause #GP, and only register a #PF handler with the enclave global exception handler registry. Clients wish to handle #GP can register its own exception handler with the global handler registry.


Public APIs
-----------------

### sgx_mm_alloc

Allocate a new memory region inside enclave and optionally register a custom page fault handler for the region

```
/**
 * Page fault (#PF) info reported in the SGX SSA MISC region.
 */
typedef struct _sgx_pfinfo
{
    uint64_t maddr;                     //address for #PF
    union _pfec {                          
        uint32_t errcd;      
        struct {//PFEC bits
            uint32_t p       : 1;    // P flag
            uint32_t rw      : 1;    // RW access flag, 0 for read, 1 for write
            uint32_t         : 13;   // U/S, I/O, PK and reserved bits not relevant for SGX PF
            uint32_t sgx     : 1;    // SGX bit
            uint32_t         : 16;   // reserved bits
        };
    } pfec;
    uint32_t reserved; 
} sgx_pfinfo;

/**
 * Custom page fault (#PF) handler, do usage specific processing upon #PF, e.g. loading data
 * and verify its trustworthiness, then call sgx_mm_commit_data to explicitly EACCEPTCOPY data.
 * This custom handler is passed into sgx_mm_alloc, and associated with the newly allocated region.
 * The memory manager calls the handler when a #PF happens in the associated region.
 * 
 * @param[in] pfinfo, info reported in the SSA MISC region for page fault
 * @param[in] private_data, private data provided by handler in sgx_mm_alloc call.
 * @return EXCEPTION_CONTINUE_EXECUTION on success handling the exception.
 *    abort if internal corruption detected. Otherwise EXCEPTION_CONTINUE_SEARCH.
 */
typedef int (*enclave_fault_handler_t)(const sgx_pfinfo* pfinfo, void* private_data);

/**
* Allocate a new memory region in enclave address space (ELRANGE).
* @param[in] addr requested address, page aligned, if NULL is provided, then the function will select the address
* @param[in] length size of the region in multiples of page size in bytes
* @param[in] flags a bitwise OR of flags describing committing mode, committing order, address preference.
*        Flags should include exactly one of following for committing mode:
*            - EMA_RESERVE: just reserve an address range, no EPC commited. To allocate memory on a reserved range, 
*                           call this function again with EMA_COMMIT_ON_DEMAND or EMA_COMMIT_NOW.
*            - EMA_COMMIT_NOW: reserves memory range and commit EPC pages. EACCEPT for all allocated pages 
*                              are done when this function returns.
*            - EMA_COMMIT_ON_DEMAND: reserves memory range, EPC pages are committed (EACCEPT) on demand upon #PF.
*        ORed with zero or one of the committing order flags:
*            - EMA_GROWSDOWN: always commit pages from higher to lower addresses, no gaps in addresses above the last committed.
*            - EMA_GROWSUP:   always commit pages from lower to higher addresses, no gaps in addresses below the last committed.
*        Optionally ORed with EMA_FIXED to indicate allocation at fixed address. 
*
* @param[in] handler, custom handler for page faults in this region, NULL if no custom handling needed
* @param[in] handler_private, private data for the @handler, which will be passed back when the handler is called.
* @param[out] out_addr, pointer to store the start address of allocated range. Set to valid address by the function on success, NULL otherwise. 
* @return 0 on success. EEXIST if range requested is overlapping a region in use and EMA_FIXED is requested,
* ENOMEM for out of memory, EACCES if region is outside enclave address space.
*/
int sgx_mm_alloc(void *addr, size_t length, int flags, enclave_fault_handler_t handler, void* handler_private, void** out_addr)
```

**Remarks:**
- If the desired address/range is in use, return a different start address if EMA_FIXED flag is not set.
- Permissions of newly allocated regions are always PROT_READ|PROT_WRiTE and page type PT_REG, except for EMA_RESERVE mode regions which will have PROT_NONE.
- Once allocated by sgx_mm_alloc, a region will stay in allocated state and become deallocated once sgx_mm_dealloc is called. 
- If sgx_mm_dealloc on a partial range of a previously allocated region, then the region is split,and the freed range is deallocated. The remainder of the region stays allocated. 
- If all pages in the region are freed by sgx_mm_dealloc, then the whole region is released, and the memory manager no longer tracks the region. 


### sgx_mm_uncommit and sgx_mm_dealloc

```
/**
* Uncommit (trim) physical EPC pages in a previously committed range. 
* The pages in the allocation are freed, but the address range is still reserved.
* @param[in] addr page aligned start address of the region to be trimmed
* @param[in] length size in bytes of multiples of page size.
* @return 0 on success, EINVAL if address range is not allocated previously, -1 on other failures
*/
int sgx_mm_uncommit(void *addr, size_t length);

/**
 * Deallocate the address range
 * The pages in the allocation are freed and the address range is released for future allocation
 * @param[in] addr page aligned start address of the region to be freed and released
 * @param[in] length size in bytes of multiples of page size.
 * @return 0 on success, EINVAL if address range is not allocated previously, -1 on other failures 
 */
int sgx_mm_dealloc(void* addr, size_t length);

```

### sgx_mm_modify_type, sgx_mm_modify_permissions and sgx_mm_modify_ex

```
/**
 * Change permissions and/or page type of a previously allocated region
 * @param[in] addr start address of the region, must be page aligned
 * @param[in] length size in bytes of page multiples.
 * @param[in] prot permissions bitwise OR of following with the same values as those defined for
 * Linux mmap/mprotect syscalls:
 *        - PROT_READ: Pages may be read.
 *        - PROT_WRITE: Pages may be written. 
 *        - PROT_EXECUTE: Pages may be executed.
 *        
 * @param[in] type page type, one of following:
 *       - PT_TCS: TCS page
 *       - PT_SS_FIRST: the first page in shadow stack
 *       - PT_SS_REST: the rest page in shadow stack
 *       - -1: no page type change, keep the original type
 * 
 * @returns 0 on success, otherwise EINVAL if the memory region was not previously allocated, or other
 * invalid parameters,  EACCES if original page type can not be changed to target type, EPERM if the request permissions
 * are not allowed (e.g., not allowed by target page type or SELinux policy), or target page type 
 * is no allowed by this call, e.g., PT_TRIM, -1 otherwise. 
 */
int sgx_mm_modify_ex(void *addr, size_t length, int prot, int type);

/**
 * Change permissions of an allocated region
 * Equivalent to sgx_mm_modify_ex(addr, length, prot, -1) 
 */
int sgx_mm_modify_permissions(void *addr, size_t length, int prot);
/**
 * Change permissions of an allocated region
 * Equivalent to sgx_mm_modify_ex(addr, length, -1, type) 
 */
int sgx_mm_modify_type(void *addr, size_t length, int type);

```
**Remarks:**
- The memory manager will track current permissions for each region, and can determine whether new permission requires OCALL for EMODPR, e.g RW<->RX, RW->R
- This API should not be used to change EPC page type to PT_TRIM. Trimming pages are done by sgx_mm_uncommit and sgx_mm_dealloc only.


### sgx_mm_commit
```
/**
* Commit a partial or full range of memory allocated previously with EMA_COMMIT_ON_DEMAND.
* The API will return 0 if all pages in the requested range are successfully committed. 
* Calling this API on pages already committed has not effect. 
* @param[in] addr, page aligned starting address
* @param[in] length, length of the region in bytes of multiples of page size.
* @return 0 on success. EINVAL if any requested page is not in any previously allocated regions, -1 otherwise 
*/
int sgx_mm_commit(void* addr, size_t length);
```

### sgx_mm_commit_data
```
/**
 * Load data into target pages within a region previously allocated by sgx_mm_alloc.
 * This can be called to load data and set target permissions at the same time, 
 * e.g. dynamic code loading. The caller has verified data to be trusted and expected 
 * to be loaded to the target address range. 
 * @param[in] addr, page aligned target starting addr
 * @param[in] length, length of data, in bytes of multiples of page size.
 * @param[in] data, data of @length
 * @param[in] prot, target permission
 * @return 0 on success. EINVAL if requested range is not in any previously allocated regions
 *                       EPERM if any pages are previously committed with different page type or permissions
 *                        -1 for other errors  
*/
int sgx_mm_commit_data(void* addr, size_t length, uint8_t* data, int prot);

```
**Remarks:**
- The memory manager decides whether OCalls are needed to request OS to make PTE permissions changes. No separate sgx_mm_modify call is needed. 


## Internal APIs and Structures

Following are internal functions and structures to be used by EMM implementation. They can evolve over time, shown here for reference only.

### Enclave Memory Area (EMA) struct

Each enclave has a global doubly linked EMA list to keep track of all dynamically allocated regions in enclave address space (ELRANGE).

```
typedef struct _ema_t  {
    size_t      start_addr;     // starting address, should be on a page boundary
    size_t      size;           // bytes
    int         alloc_flags;    // EMA_RESERVED, EMA_COMMIT_NOW, EMA_COMMIT_ON_DEMAND, OR'ed with EMA_SYSTEM, EMA_GROWSDOWN, ENA_GROWSUP
    int         perms;          // EMA_NOACCESS, READONLY, READWRITE, EXECUTE_READ, EXECUTE_READWRITE
    int         page_type;      // EMA_PT_REG, EMA_PT_TCS, EMA_PT_TRIM
    uint8_t*    eaccept_map;    // bitmap for EACCEPT status, bit 0 in eaccept_map[0] for the page at start address
                                // bit i in eaccept_map[j] for page at start_address+(i+j<<3)<<12
    mutex_t     lock;           // lock to prevent concurrent modification, could be sgx_thread_mutex_t/rwlock_t
    int         transition;     // state to indicate whether a transition in progress, e.g page type/permission changes
    enclave_fault_handler_t h;  // custom PF handler  (for EACCEPTCOPY use)
    void*       hprivate;       // private data for handler
    ema_t*      next;           // next in doubly linked list
    ema_t*      prev;           // prev in doubly linked list
} ema_t;

```
 **Remarks:** 
 - Access to the list (find, insert, remove EMAs) are synchronized for thread-safety.
 - Initial implementation will also have one lock per EMA to synchronize access and modifications to the same EMA. We may optimize this as needed.

### SGX primitives

```
typedef struct _sec_info_t
{
   uint64_t         flags;
   uint64_t         reserved[7];
} sec_info_t;

// EACCEPT 
int do_eaccept(const sec_info_t * si, size_t addr);
//EMODPE
int do_emodpe(const sec_info_t* si, size_t addr);
//EACCEPTCOPY
int do_eacceptcopy(const sec_info_t * si, size_t dest, size_t src);
```
### OCalls

```
/**
 * Call OS mmap to reserve region for EAUG, immediately or on-demand
 * @param[in] addr, desired page aligned start address, NULL if no desired address
 * @param[in] length, size of the region in multiples of page size in bytes
 * @param[in] flags, must be MAP_SHARED | MAP_FIXED masked with optional flags:
 *              MAP_POPULATE: hint for kernel to EAUG pages as soon as possible.
 *              MAP_GROWSDOWN: used for stacks. The mapping will grow down to the next mapping.
 * @param[out] out_addr, start address of region reserved by OS
 * @return 0 on success, or error code similar to mmap
 */
int mmap_ocall(void* addr, size_t length, int flags, void** out_addr);
/**
 *
 * call OS mprotect to change permission, type, or notify EACCEPT done after TRIM
 * 
 * @param[in] addr, start address of the memory to change protections
 * @param[in] length, length of the area.  This must be a multiple of the page size.
 * @param[in] prot, this must be OR'ed of following:
 *            PROT_READ
 *            PROT_WRITE
 *            PROT_EXEC
 *            PROT_TRIM: change the page type to PT_TRIM, implies RW. 
 *            PROT_TCS: change the page type to PT_TCS
 *            PROT_SS_FIRST
 *            PROT_SS_REST
 *            PROT_NONE: Signal the kernel EACCEPT is done for PT_TRIM pages. 
 * @return 0 on success, or error code similar to mprotect
 */

mprotect_ocall(void*addr, int flags)

```

Metadata,  File format
---------------------------------------

Enclave metadata and file format are runtime specific. Detailed design is out of scope of this document.
It is required that the enclave file should include metadata of memory layout of initial code and data (e.g., program headers and PT_LOAD segments in ELF file), any reserved region for special purposes, e.g. minimal heap, stack, TCS areas, SSAs for expected minimal number of threads, etc.
 

EMM Initialization and Tracking Initially Committed (EADDed) Regions
---------------------------------------------------------------------

The memory manager must be initialized in first ECALL (ECMD_INIT_ENCLAVE in Intel SGX SDK) before any other clients can use it. Therefore, code and data of the memory manager will be part of initial enclave image that are loaded with EADD before EINIT, and as a part of the trusted runtime. 

The trusted runtime should enumerate all initial committed regions (code, data, heap, stack, TCS, SSA), and call the EMM internal APIs to setup initial entries in the EMA list to track existing regions and mark some of them not modifiable by EMM public APIs. Runtime also ensures there is enough reserved space on heap for EMM to create the initial EMA list and the entries. Once initialized, the memory manager can reserve its own space for future expansion of the EMA list, and special EMAs to hold EMA objects. To keep it simple, the expansion can be done eagerly: commit more pages for EMA list once unused committed space in the EMA List Region below certain threshold.

Alternative option: At build time, signing tool can precalculate and fill in EMA entries that holds info of initial regions to be committed by EADD during enclave load. The calculated start addresses in these EMAs can be relative to enclave secs->base. Runtime can patch those entries at initialization by adding secs->base. The EMM can directly use those EMAs as the initial entries of the EMA list. It only needs to reserve and commit an inital number of additional pages for future EMA list expansion.  


## Private APIs
Private APIs are used by the trusted runtime to reserve and allocate regions not accessible from public APIs. 
They have exact signature as the public API counterparts and replace "sgx_mm_" prefix with "ema_" prefix.
The main difference is that the private ema_alloc allows an extra flag EMA_SYSTEM passed in.

```
/**
 * Same as sgx_mm_alloc, EMA_SYSTEM can be OR'ed with flags to indicate that the EMA can not be modified thru public APIs
 */
int ema_alloc(void *addr, size_t length, int flags, enclave_fault_handler_t handler, void* handler_private, void** out_addr);

int ema_dealloc(void* addr, size_t length);
int ema_uncommit(void *addr, size_t length);

int ema_commit(void* addr, size_t length);

int ema_commit_data(void* addr, size_t length, uint8_t* data, int prot);

int ema_modify_ex(void *addr, size_t length, int prot, int type);

```
