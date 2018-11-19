<h1>Open Enclave API Specification</h1>

## 1. API

### 1.1 Summary
Trusted Execution Environments (TEEs) such as Intel’s SGX, ARM’s TrustZone, Secure Elements, etc. provide a hardware-enforced execution environment that is protected from malware, even in the face of buffer overruns, kernel rootkits, etc.  Currently Intel has an Intel-specific API, and GlobalPlatform has another API specific to ARM and SecureElements.   OpenEnclave APIs provide a processor-agnostic set of APIs over an open-source implementation.

These APIs let a developer write code to be run in a Trusted Execution Environment (once that code is properly signed and authorized), as well as code in a normal application that can communicate with such trusted code.

There are also emulator environments for development use which do not require hardware capability, and there are virtualized environments using VMs as well, and so the APIs are functional in such cases even when a device does not have TEE hardware support.

### 1.2 Features
The following features are supported:
    * Allow writing trusted application code that is processor agnostic, e.g., working with either SGX or TrustZone.
    * Allow writing trusted application code that is OS-agnostic, e.g., working with either Windows or Linux.
    * Allow trusted application code to store sealed data that only it can read (at least in unencrypted form).
    * Allow two trusted application components (on the same machine or on different machines) to attest to each other securely.

### 1.3 Scenarion 1: Basic Trusted Application
This sample shows how trusted application code is loaded, and how normal application code and trusted application code can communicate using an (L)RPC based API the app developer defines in an EDL file.

#### 1.3.1 EDL file
```
enclave {
    trusted {
        /* APIs exposed by trusted application code */
        public int enclave_helloworld();
    };

    untrusted {
        /* APIs exposed by the normal application */
        int host_helloworld();
    };
};
```

#### 1.3.2	Normal application code
The following code shows how oe_create_enclave and oe_terminate_enclave can be used to start/stop trusted application code (similar to LoadLibrary/FreeLibrary in Windows).  It also illustrates that calls into trusted application code can be done using code generated from the EDL file, which in this example was named "sample.edl” and so generated, among other things, an API called oe_create_sample_enclave().
```
// API that the enclave code can call back into.
int host_helloworld(void)
{
    return printf("Enclave called into host to print: Hello World!\n");
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    int ret = 1;
    oe_enclave_t* enclave = NULL;
    uint32_t enclave_flags = 0;

    // Try to create the enclave.
#ifdef _DEBUG
    enclave_flags |= OE_ENCLAVE_FLAG_DEBUG;
#endif
    result = oe_create_sample_enclave("MyEnclave", // Base filename, without extension.
                                      OE_ENCLAVE_TYPE_UNDEFINED,
                                      enclave_flags, NULL, 0, &enclave);
    if (result != OE_OK) {
        fprintf(stderr,
                "oe_create_sample_enclave(): result=%u (%s)\n",
                result,
                oe_result_str(result));
        goto exit;
    }

    // Call into the enclave.
    int hostResult;
    result = enclave_helloworld(enclave, &hostResult);
    if (result != OE_OK) {
        fprintf(stderr,
                "calling into enclave_helloworld failed: result=%u (%s)\n",
                result,
                oe_result_str(result));
        goto exit;
    }
    if (hostResult != OE_OK) {
        fprintf(stderr, "OCALL failed: result=%u", hostResult);
        goto exit;
    }

    ret = 0;

exit:
    // Clean up the enclave if we created one
    if (enclave)
        oe_terminate_enclave(enclave);

    return ret;
}
```

#### 1.3.3 Trusted application code
The following code illustrates that trusted application code can be written using only standard C APIs (e.g., printf), and that calls to normal application code can be done using code generated from the EDL file.   It also shows a call to oe_result_str() to convert a result code into a string message for diagnostic purposes.
```
// This is the function that the host calls. It prints a message in the enclave before
// calling back out to the host to print a message from there too.
int enclave_helloworld(void)
{
    // Print a message from the enclave. Note that this does not directly call printf,
    // but calls into the host and calls printf from there. This is because the printf
    // function is not part of the enclave as it requires support from the kernel.
    printf("Hello world from the enclave\n");

    // Call back into the host
    int retval;
    oe_result_t result = host_helloworld(&retval);
    if (result != OE_OK) {
        fprintf(stderr,
                "Call to host_helloworld failed: result=%u (%s)\n",
                result,
                oe_result_str(result));
    }
    return result;
```
### 1.4 Scenario 2: Sealing/unsealing trusted application data
In this scenario, the app wants to have a secret key that it can use to encrypt (or “seal”) its own data for storage in an untrusted location, so that it can later (e.g., when starting up again) retrieve the same data.

####  1.4.1 Trusted application code
```
#define OE_API_VERSION 2 // Temporary, until v2 is the default

void EncryptWithKey(uint8_t** outKeyInfo, size_t* outKeyInfoSize)
{
    uint8_t* key;
    uint8_t* keyInfo;
    size_t keySize;
    size_t keyInfoSize;
    oe_result_t oeResult;

    oeResult = oe_get_seal_key_by_policy(OE_SEAL_POLICY_PRODUCT, &key, &keySize,
                                         &keyInfo, &keyInfoSize);
    // … handle failure …

    // … Use the key to do encryption somehow …


    oe_free_key(key, NULL);
    // Pass keyInfo back to caller to free when done. Trusted application code
    // can free it using oe_free_key(), or normal application code can free it
    // using free().
    // The keyInfo represents a non-secret identifier that can be used to retrieve
    // the key later, such as to decrypt.
    *outKeyInfo = keyInfo;
    *outKeyInfoSize = keyInfoSize;
}

void DecryptWithKey(const uint8_t* keyInfo, size_t keyInfoSize)
{
    uint8_t* key;
    size_t keySize;
    oe_result_t oeResult;

    oeResult = oe_get_seal_key(&keyInfo, keyInfoSize, &key, &keySize);
    // … handle failure …

    // … Use the key to do decryption somehow …


    oe_free_key(key, keyInfo);
}
```

### 1.5 Scenario 3: Attestation
In this scenario, an application wants to get a report that can attest to the integrity of a trusted application, and verify a report that it received from another trusted application (e.g., across a TLS connection).  This can be triggered from either normal application code or trusted application code, with similar APIs, but in either case, the operation is actually performed and signatures generated or checked within the Trusted Execution Environment (i.e., by the library linked into the trusted application code).

#### 1.5.1 Trusted application code example
```
#define OE_API_VERSION 2 // Temporary, until v2 is the default

oe_result_t SendOwnReport()
{
    oe_result_t oeResult;
    size_t ownReportSize;
    uint8_t* ownReport;
    oeResult = oe_get_report(0, NULL, 0, &ownReport, &ownReportSize);
    if (oeResult != OE_OK) {

        return oeResult;
    }

    // Send the report buffer to a peer somehow.
    // …

    // Free the report.

    oe_free_report(ownReport);
    return OE_OK;
}
    
// This might be called when a peer’s report is received across a network connection,
// and will return success if the peer’s report is considered authentic.
oe_result_t VerifyPeerReport(const uint8_t* peerReport, size_t peerReportSize)
{
    // Verify that the report is considered authentic, and if so, get a parsed
    // report.  We could also do this in two steps by using oe_parse_report
    // to get the parsed_report and just pass NULL to oe_verify_report.
    oe_report_t parsed_report;
    oe_result_t oeResult = oe_verify_report(peerReport,
                                            peerReportSize,
                                            &parsed_report);
    if (oeResult != OE_OK) {
        return oeResult;
    }

    // We can now safely use the information in the parsed report to make
    // app-specific authorization decisions.
    if (!IsAuthorized(parsed_report.unique_id)) {
        return OE_FAILURE;
    }

    return OE_OK;
}
```

#### 1.5.2 Normal application code example
This code is similar to the trusted application code, except that the normal application has to specify which enclave to use, since the same normal application might be using multiple enclaves simultaneously, each of which would have their own identity and report.
```
#define OE_API_VERSION 2 // Temporary, until v2 is the default

oe_result_t SendOwnReport()
{
    oe_result_t oeResult;
    size_t ownReportSize;

    uint8_t* ownReport;
    oeResult = oe_get_report(enclave, 0, NULL, 0, &ownReport, &ownReportSize);
    if (oeResult != OE_OK) {

        return oeResult;
    }

    // Send the report buffer to a peer somehow.
    // …

    // Free the report.

    oe_free_report(ownReport);
    return OE_OK;
}
    
// This might be called when a peer’s report is received across a network connection,
// and will return success if the peer’s report is considered authentic.
oe_result_t VerifyPeerReport(oe_enclave_t* enclave,
                             const uint8_t* peerReport, size_t peerReportSize)
{
    // Verify that the report is considered authentic.
    oe_result_t oeResult = oe_verify_report(enclave,
                                            peerReport,
                                            peerReportSize,
                                            NULL);
    if (oeResult != OE_OK) {
        return oeResult;
    }

    // We could make authorization decisions using the parsed report, but since
    // this check is not in the Trusted Execution Environment, it may be susceptible
    // to malware.  However, we might use a parsed report just for display purposes.
#ifdef _DEBUG
    oe_report_t parsed_report;
    oeResult = oe_parse_report(report_buffer, report_buffer_size, &parsed_report);

    printf("Report verified from %s\n",
           ConvertToHexString(parsed_report.unique_id,
                              sizeof(parsed_report.unique_id));
#endif
                          
    return OE_OK;
}
```

### 1.6	Scenario 4: Secure callback context
In this scenario, an enclave wants to provide a handle to some state it has, that a normal application can use in subsequent calls.  For example, to start a widget service of some sort, and later stop it.  This illustrates that the trusted application code does not need to invent its own handle mechanism, nor does it need to pass a pointer back to the normal world and somehow check whether it is legal, which would be risky at best.

#### 1.6.1 EDL file
```
enclave {
    trusted {
        /* APIs exposed by trusted application code */
        public uint32_t enclave_start_widget();
        public void enclave_stop_widget(uint32_t handle);
    };
};
```

#### 1.6.2 Normal application code
```
void RunWidgetForOneMinute(enclave_t* enclave)
{
    uint32_t handle;
    oe_result_t oeResult = enclave_start_widget(enclave, &handle);
    if (oeResult != OE_OK || handle == OE_INVALID_HANDLE_VALUE) {
        // … handle failure …
    }

    oeResult = enclave_stop_widget(enclave, handle);
    if (oeResult != OE_OK) {
        // … handle failure …
    }
}
```

#### 1.6.3 Trusted application code
```
ptrdiff_t enclave_start_widget(void)
{
    my_widget_t* widget = (my_widget_t*)malloc(sizeof(*widget));
    // … handle allocation failure …
    // … initialize widget state …

    ptrdiff_t handle;
    oe_result_t oeResult = oe_allocate_handle(widget, &handle);
    if (oeResult != OE_OK) {
        return OE_INVALID_HANDLE_VALUE;
    }    

    return handle;
}

void enclave_stop_widget(ptrdiff_t handle)
{
    my_widget_t* widget;
    oe_result_t oeResult = oe_resolve_handle(handle, &widget);
    if (oeResult != OE_OK) {
        // … handle failure …
    }

    // … use widget normally …

    // Remove handle, which means any subsequent calls to oe_resolve_handle()
    // will fail for this handle.
    oe_free_handle(handle);

    // … make sure there’s no other uses of the widget pointer. If the trusted
    // application is multithreaded, this also means that thread synchronization
    // must be handled and only continue once no references remain …

    // Clean up widget state.
    free(widget);
}
```

### 1.7	Interface Definition

#### 1.7.1 Common APIs
The following APIs are exposed to normal applications as well as trusted application code.

##### 1.7.1.1 Standard C file APIs
The following file APIs that operate on already-opened files are exposed to trusted applications as well:
* fflush, ferror, fclose, feof, fread, fseek, ftell, fwrite, fputs, fgets
These are #define’ed to oe_* equivalents by default, which have the same syntax as the POSIX equivalents:
* oe_fopen, oe_fflush, oe_ferror, oe_fclose, oe_feof, oe_fread, oe_fseek, oe_ftell, oe_fwrite, oe_fputs, oe_fgets
The following file APIs are exposed to trusted applications as well:
* fopen

These are #define’ed to oe_* equivalents by default, which have the same syntax as the POSIX equivalents, equivalents, except they have an additional security mode argument:
```
OE_FILE *oe_fopen(oe_file_security_t file_security, const char *path, const char *mode);
```
The file security argument is:
```
typedef enum {
    OE_FILE_INSECURE = 0,
    OE_FILE_SECURE_HARDWARE = 1,
    OE_FILE_SECURE_ENCRYPTION = 2,
    OE_FILE_SECURE_BEST_EFFORT = 3,  /** Hardware if it exists, else encryption. */
    // … possibly other modes …
} oe_file_security_t;
```
OE_FILE_SECURE_HARDWARE allows access to secure files that are protected against normal application code.  (On SGX, this can be done using encrypted files stored in the filesystem, such that they can only be decrypted from within the enclave.  On TrustZone, this can be done with files that are in secure storage, invisible to the normal world.)  As such, encryption need not be done by the application.

The mappings from the non-prefixed, standard POSIX names can be configured by the trusted application using the OE_SECURE_POSIX_FILE_API define, but default to the untrusted storage variants. Trusted application code can control which ones the POSIX names map to using the OE_SECURE_POSIX_FILE_API define, which is implemented as follows:
```
#ifdef OE_SECURE_POSIX_FILE_API
#define fopen(path, mode) oe_fopen(OE_FILE_SECURE_BEST_EFFORT, path, mode)
#else if !defined(OE_NO_POSIX_FILE_API)
#define fopen(path, mode) oe_fopen(OE_FILE_INSECURE, path, mode)
#endif
```
The following POSIX file enumeration APIs are exposed to trusted applications as well.
* closedir, opendir, readdir

These map to their oe_* equivalents by default, where opendir has the additional argument:
```
DIR *oe_opendir(oe_file_security_t file_security, const char *name);

#ifdef OE_SECURE_POSIX_FILE_API
#define opendir(name) \
    oe_opendir(OE_FILE_SECURE_BEST_EFFORT, name)
#else if !defined(OE_NO_POSIX_FILE_API)
#define opendir(name) \
    oe_opendir(OE_FILE_INSECURE, name)
#endif

int oe_closedir(OE_DIR *dirp);
struct oe_dirent *oe_readdir(OE_DIR *dirp);
```

##### 1.7.1.2 Standard C networking APIs
The following POSIX socket APIs are exposed to trusted applications as well, and do not hit the network:  
* htonl, htons, inet_addr, ntohl, ntohs

These are #define’d to oe_* equivalents, which have the same syntax as the POSIX equivalents:
* oe_htonl, oe_htons, oe_inet_addr, oe_ntohl, oe_ntohs

The following POSIX socket APIs are also exposed, which do involve a network stack:
* accept, bind, connect, FD_ISSET, freeaddrinfo, getpeername, getsockname, getsockopt, listen, recv, select, send, setsockopt, shutdown
* These are #define’ed to oe_* equivalents by default, which have the same syntax as the POSIX equivalents:  oe_accept, oe_bind, oe_connect, oe_fd_isset, oe_freeaddrinfo, oe_getpeername, oe_getsockname, oe_getsockopt, oe_listen, oe_recv, oe_select, oe_send, oe_setsockopt, oe_shutdown 

The following POSIX socket APIs are exposed to trusted applications as well:
* socket, getaddrinfo, gethostname, getnameinfo
* These are #defined to oe_* equivalents by default, which have the same syntax as the POSIX equivalents, except they have an additional security mode argument (the former list all have sockets as input arguments, unlike the ones below):oe_socket, oe_getaddrinfo, oe_gethostname, oe_getnameinfo

Example:
```
typedef enum {
    OE_NETWORK_INSECURE = 0,
    OE_NETWORK_SECURE_HARDWARE = 1,
    // … possibly other modes …
} oe_network_security_t;
 
int oe_socket(oe_network_security_t network_security, int domain, int type, int protocol);

#ifdef OE_SECURE_POSIX_NETWORK_API
#define socket(domain, type, protocol) \
    oe_socket(OE_NETWORK_SECURE_HARDWARE, domain, type, protocol)
#else if !defined(OE_NO_POSIX_SOCKET_API)
#define socket(domain, type, protocol) \
    oe_socket(OE_NETWORK_UNTRUSTED, domain, type, protocol)
#endif
```

OE_NETWORK_SECURE_HARDWARE allows access to secure network connections, if such exist on the platform, that are protected against normal application code.

The following Winsock APIs that accept sockets are also exposed to trusted applications as well, to ease porting of normal Windows applications:
* closesocket, ioctlsocket

These are #define’ed to oe_* equivalents by default, most of which have the same syntax as the POSIX equivalents:  
* oe_closesocket, oe_ioctlsocket

The following other Winsock APIs are also exposed to ease porting of normal Windows apps:
* WSACleanup, WSAGetLastError, WSASetLastError, WSAStartup

These are #define’ed to oe_* equivalents by default, which have the same syntax as the Winsock equivalents except for an additional oe_network_security_t argument.  
* oe_wsa_cleanup, oe_wsa_get_last_error, oe_wsa_set_last_error, oe_wsa_startup

##### 1.7.1.3 Standard C time APIs
The following [relative time POSIX APIs](http://pubs.opengroup.org/onlinepubs/9699919799/functions/clock_getres.html) should be exposed to trusted applications as well:
* clock_getres, clock_gettime, clock_settime

These are #define’ed to oe_* equivalents, which have the same syntax as the POSIX equivalents except for the additional time security argument.
```
#ifdef OE_SECURE_POSIX_TIME_API
#define clock_gettime(clk_id, tp) \
    oe_clock_gettime(OE_TIME_SECURE_HARDWARE, clk_id, tp)
#else if !defined(OE_NO_POSIX_TIME_API)
#define clock_gettime(clk_id, tp) \
    oe_clock_gettime(OE_TIME_INSECURE, clk_id, tp)
#endif
```

##### 1.7.1.4 openenclave/bits/defs.h
```
/* OE_API_VERSION */
#ifndef OE_API_VERSION
#define OE_API_VERSION 1
#endif

/* OE_PRINTF_FORMAT */
#if defined(__GNUC__) && (__GNUC__ >= 4)
#define OE_PRINTF_FORMAT(N, M) __attribute__((format(printf, N, M)))
#else
#define OE_PRINTF_FORMAT(N, M) /* empty */
#endif

/* OE_UNUSED */
#define OE_UNUSED(P) (void)(P)

/* OE_ALWAYS_INLINE */
#if defined(__linux__)
#define OE_ALWAYS_INLINE __attribute__((always_inline))
#elif defined(_WIN32)
#define OE_ALWAYS_INLINE __forceinline
#endif

/* OE_NEVER_INLINE */
#ifdef _MSC_VER
#define OE_NEVER_INLINE __declspec(noinline)
#elif __GNUC__
#define OE_NEVER_INLINE __attribute__((noinline))
#endif

/* OE_INLINE */
#ifdef _MSC_VER
#define OE_INLINE static __inline
#elif __GNUC__
#define OE_INLINE static __inline__
#endif

#ifdef _MSC_VER
#define OE_NO_OPTIMIZE_BEGIN __pragma(optimize("", off))
#define OE_NO_OPTIMIZE_END __pragma(optimize("", on))
#elif __clang__
#define OE_NO_OPTIMIZE_BEGIN _Pragma("clang optimize off")
#define OE_NO_OPTIMIZE_END _Pragma("clang optimize on")
#elif __GNUC__
#define OE_NO_OPTIMIZE_BEGIN \
    _Pragma("GCC push_options") _Pragma("GCC optimize(\"O0\")")
#define OE_NO_OPTIMIZE_END _Pragma("GCC pop_options")
#else
#error "OE_NO_OPTIMIZE_BEGIN and OE_NO_OPTIMIZE_END not implemented"
#endif

#if defined(__cplusplus)
#define OE_EXTERNC extern "C"
#define OE_EXTERNC_BEGIN extern "C" {
#define OE_EXTERNC_END }
#else
#define OE_EXTERNC
#define OE_EXTERNC_BEGIN
#define OE_EXTERNC_END
#endif

/*
 * Export a symbol, so it can be found as a dynamic symbol later for
 * ecall/ocall usage.
 */
#ifdef __GNUC__
#define OE_EXPORT __attribute__((visibility("default")))
#elif _MSC_VER
#define OE_EXPORT __declspec(dllexport)
#else
#error "OE_EXPORT unimplemented"
#endif

/*
 * Export a constant symbol.
 * In C, the symbol is annotated with OE_EXPORT const.
 * In C++, const symbols by default have internal linkage.
 * Therefore, the symbol is annotated with OE_EXPORT extern const
 * to ensure extern linkage and prevent compiler warnings.
 */
#if defined(__cplusplus)
#define OE_EXPORT_CONST OE_EXPORT extern const
#else
#define OE_EXPORT_CONST OE_EXPORT const
#endif

/* OE_ALIGNED */
#ifdef __GNUC__
#define OE_ALIGNED(BYTES) __attribute__((aligned(BYTES)))
#elif _MSC_VER
#define OE_ALIGNED(BYTES) __declspec(align(BYTES))
#else
#error OE_ALIGNED not implemented
#endif

/* OE_COUNTOF */
#define OE_COUNTOF(ARR) (sizeof(ARR) / sizeof((ARR)[0]))

/* OE_OFFSETOF */
#ifdef __GNUC__
#define OE_OFFSETOF(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#elif _MSC_VER
#ifdef __cplusplus
#define OE_OFFSETOF(TYPE, MEMBER) \
    ((size_t) & reinterpret_cast<char const volatile&>((((TYPE*)0)->MEMBER)))
#else
#define OE_OFFSETOF(TYPE, MEMBER) ((size_t) & (((TYPE*)0)->MEMBER))
#endif
#else
#error OE_OFFSETOF not implemented
#endif

/* NULL */
#ifndef NULL
#ifdef __cplusplus
#define NULL 0L
#else
#define NULL ((void*)0)
#endif
#endif

/* OE_ECALL */
#define OE_ECALL OE_EXTERNC OE_EXPORT __attribute__((section(".ecall")))

/* OE_OCALL */
#define OE_OCALL OE_EXTERNC OE_EXPORT

/* The maxiumum value for a four-byte enum tag */
#define OE_ENUM_MAX 0xffffffff

/* OE_DEPRECATED */
#if defined(__GNUC__)
#define OE_DEPRECATED(FUNC, MSG) FUNC __attribute__((deprecated(MSG)))
#elif defined(_MSC_VER)
#define OE_DEPRECATED(FUNC, MSG) __declspec(deprecated(MSG)) FUNC
#else
#define OE_DEPRECATED(FUNC, MSG) FUNC
#endif
```

##### 1.7.1.5 openenclave/bits/report.h
This file defines structures and options passed to oe_get_report functions.
```
/**
 * Flags passed to oe_get_report functions on host and enclave.
 * Default value (0) is local attestation.
 */
#define OE_REPORT_FLAGS_REMOTE_ATTESTATION 0x00000001

/**
 * Size of embedded data in a local report.
 */
#define OE_REPORT_DATA_SIZE 64

/**
 * Maximum report size supported by OE. This is 10 KB.
 */
#define OE_MAX_REPORT_SIZE (10 * 1024)

/**
 * @cond DEV
 */
// Fixed identity property sizes for OEv1
/**
 * Size of the enclave's unique ID in bytes.
 */
#define OE_UNIQUE_ID_SIZE 32
/**
 * Size of the enclave's signer ID in bytes.
 */
#define OE_SIGNER_ID_SIZE 32
/**
 * Size of the enclave's product ID in bytes.
 */
#define OE_PRODUCT_ID_SIZE 16

/**
 * Bit mask for a debug report.
 */
#define OE_REPORT_ATTRIBUTES_DEBUG 0x0000000000000001ULL
/**
 * Bit mask for a remote report.
 */
#define OE_REPORT_ATTRIBUTES_REMOTE 0x0000000000000002ULL
/**
 * Reserved bits.
 */
#define OE_REPORT_ATTRIBUTES_RESERVED \
    (~(OE_REPORT_ATTRIBUTES_DEBUG | OE_REPORT_ATTRIBUTES_REMOTE))

/**
 * @endcond
 */

/**
 * Structure to represent the identity of an enclave.
 * This structure is expected to change in future.
 * Newer fields are always added at the end and fields are never removed.
 * Before accessing a field, the enclave must first check that the field is
 * valid using the id_version and the table below:
 *
 * id_version | Supported fields
 * -----------| --------------------------------------------------------------
 *     0      | security_version, attributes, unique_id, signer_id, product_id
 */
typedef struct _oe_identity
{
    /** Version of the oe_identity_t structure */
    uint32_t id_version;

    /** Security version of the enclave. For SGX enclaves, this is the
      *  ISVN value */
    uint32_t security_version;

    /** Values of the attributes flags for the enclave -
     *  OE_REPORT_ATTRIBUTES_DEBUG: The report is for a debug enclave.
     *  OE_REPORT_ATTRIBUTES_REMOTE: The report can be used for remote
     *  attestation */
    uint64_t attributes;

    /** The unique ID for the enclave.
      * For SGX enclaves, this is the MRENCLAVE value */
    uint8_t unique_id[OE_UNIQUE_ID_SIZE];

    /** The signer ID for the enclave.
      * For SGX enclaves, this is the MRSIGNER value */
    uint8_t signer_id[OE_SIGNER_ID_SIZE];

    /** The Product ID for the enclave.
     * For SGX enclaves, this is the ISVPRODID value. */
    uint8_t product_id[OE_PRODUCT_ID_SIZE];
} oe_identity_t;

/**
 * Structure to hold the parsed form of a report.
 */
typedef struct _oe_report
{
    /** Size of the oe_report_t structure. */
    size_t size;

    /** The enclave type. */
    oe_enclave_type_t type;

    /** Size of report_data */
    size_t report_data_size;

    /** Size of enclave_report */
    size_t enclave_report_size;

    /** Pointer to report data field within the report byte-stream supplied to
     * oe_parse_report */
    uint8_t* report_data;

    /** Pointer to report body field within the report byte-stream supplied to
     * oe_parse_report. */
    uint8_t* enclave_report;

    /** Contains the IDs and attributes that are part of oe_identity_t */
    oe_identity_t identity;
} oe_report_t;
```

##### 1.7.1.6 openenclave/bits/result.h
This file defines Open Enclave return codes (results).
```
/**
 * This enumeration type defines return codes for Open Enclave functions.
 * These functions return **OE_OK** upon success and one of the other
 * enumeration values on failure.
 */
typedef enum _oe_result {

    /**
     * The function was successful.
     */
    OE_OK,

    /**
     * The function failed (without a more specific error code).
     */
    OE_FAILURE,

    /**
     * One or more output buffer function parameters is too small.
     */
    OE_BUFFER_TOO_SMALL,

    /**
     * One or more input function parameters is invalid. Either the value of
     * an input parameter is invalid or a required input parameter pointer
     * is null.
     */
    OE_INVALID_PARAMETER,

    /**
     * The host attempted to perform a reentrant **ECALL**. This occurs when an
     * **OCALL** function attempts to perform an **ECALL**.
     */
    OE_REENTRANT_ECALL,

    /**
     * The function is out of memory. This usually occurs when **malloc** or
     * a related function returns null.
     */
    OE_OUT_OF_MEMORY,

    /**
     * The function is unable to bind the current host thread to an enclave
     * thread. This occurs when the host performs an **ECALL** while all enclave
     * threads are in use.
     */
    OE_OUT_OF_THREADS,

    /**
     * The function encountered an unexpected failure.
     */
    OE_UNEXPECTED,

    /**
     * A cryptographic verification failed. Examples include:
     *     - enclave quote verification
     *     - public key signature verification
     *     - certificate chain verification
     */
    OE_VERIFY_FAILED,

    /**
     * The function failed to find a resource. Examples of resources include
     * files, directories, and functions (ECALL/OCALL), container elements.
     */
    OE_NOT_FOUND,

    /**
     * The function encountered an overflow in an integer operation, which
     * can occur in arithmetic operations and cast operations.
     */
    OE_INTEGER_OVERFLOW,

    /**
     * The certificate does not contain a public key.
     */
    OE_PUBLIC_KEY_NOT_FOUND,

    /**
     * An integer index is outside the expected range. For example, an array
     * index is greater than or equal to the array size.
     */
    OE_OUT_OF_BOUNDS,

    /**
     * The function prevented an attempt to perform an overlapped copy, where
     * the source and destination buffers are overlapping.
     */
    OE_OVERLAPPED_COPY,

    /**
     * The function detected a constraint failure. A constraint restricts the
     * the value of a field, parameter, or variable. For example, the value of
     * **day_of_the_week** must be between 1 and 7 inclusive.
     */
    OE_CONSTRAINT_FAILED,

    /**
     * An **IOCTL** operation failed. Open Enclave uses **IOCTL** operations to
     * communicate with the Intel SGX driver.
     */
    OE_IOCTL_FAILED,

    /**
     * The given operation is unsupported, usually by a particular platform
     * or environment.
     */
    OE_UNSUPPORTED,

    /**
     * The function failed to read data from a device (such as a socket, or
     * file).
     */
    OE_READ_FAILED,

    /**
     * A software service is unavailable (such as the AESM service).
     */
    OE_SERVICE_UNAVAILABLE,

    /**
     * The operation cannot be completed because the enclave is aborting.
     */
    OE_ENCLAVE_ABORTING,

    /**
     * The operation cannot be completed because the enclave has already
     * aborted.
     */
    OE_ENCLAVE_ABORTED,

    /**
     * The underlying platform or hardware returned an error. For example,
     * an SGX user-mode instruction failed.
     */
    OE_PLATFORM_ERROR,

    /**
     * The given **CPUSVN** value is invalid. An SGX user-mode instruction may
     * return this error.
     */
    OE_INVALID_CPUSVN,

    /**
     * The given **ISVSNV** value is invalid. An SGX user-mode instruction may
     * return this error.
     */
    OE_INVALID_ISVSVN,

    /**
     * The given **key name** is invalid. An SGX user-mode instruction may
     * return this error.
     */
    OE_INVALID_KEYNAME,

    /**
     * Attempted to create a debug enclave with an enclave image that does
     * not allow it.
     */
    OE_DEBUG_DOWNGRADE,

    /**
     * Failed to parse an enclave report.
     */
    OE_REPORT_PARSE_ERROR,

    /**
     * The certificate chain is not available or missing.
     */
    OE_MISSING_CERTIFICATE_CHAIN,

    /**
     * An operation cannot be performed because the resource is busy. For
     * example, a non-recursive mutex cannot be locked because it is already
     * locked.
     */
    OE_BUSY,

    /**
     * An operation cannot be performed because the requestor is not the
     * owner of the resource. For example, a thread cannot lock a mutex
     * because it is not the thread that acquired the mutex.
     */
    OE_NOT_OWNER,

    /**
     * The certificate does not contain the expected SGX extensions.
     */
    OE_INVALID_SGX_CERTIFICATE_EXTENSIONS,

    /**
     * A memory leak was detected during enclave termination.
     */
    OE_MEMORY_LEAK,

    /**
     * The data is improperly aligned for the given operation. This may occur
     * when an output buffer parameter is not suitably aligned for the data
     * it will receive.
     */
    OE_BAD_ALIGNMENT,

    /**
     * Failed to parse the trusted computing base (TCB) revocation data
     * for the enclave.
     */
    OE_TCB_INFO_PARSE_ERROR,

    /**
     * The level of the trusted computing base (TCB) is not up to date for
     * report verification.
     */
    OE_TCB_LEVEL_INVALID,

    /**
     * Failed to load the quote provider library used for quote generation
     * and attestation.
     */
    OE_QUOTE_PROVIDER_LOAD_ERROR,

    /**
     * A call to the quote provider failed.
     */
    OE_QUOTE_PROVIDER_CALL_ERROR,

    /**
     * The certificate revocation data for attesting the trusted computing
     * base (TCB) is invalid for this enclave.
     */
    OE_INVALID_REVOCATION_INFO,

    /**
     * The given UTC date-time string or structure is invalid. This occurs
     * when (1) an element is out of range (year, month, day, hours, minutes,
     * seconds), or (2) the UTC date-time string is malformed.
     */
    OE_INVALID_UTC_DATE_TIME,

    __OE_RESULT_MAX = OE_ENUM_MAX,
} oe_result_t;

/**
 * Retrieve a string for a result code.
 *
 * This function retrieves a string description for the given **result**
 * parameter.
 *
 * @param result Retrieve string description for this result code.
 *
 * @returns Returns a pointer to a static string description.
 *
 */
const char* oe_result_str(oe_result_t result);
```

##### 1.7.1.7 openenclave/bits/types.h
```
/* Basic types */
#if defined(__GNUC__)
typedef long ssize_t;
typedef unsigned long size_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int64_t;
typedef unsigned long uint64_t;
typedef unsigned long uintptr_t;
typedef long ptrdiff_t;
#elif defined(_MSC_VER)
typedef long long ssize_t;
typedef unsigned long long size_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef unsigned long long uintptr_t;
typedef long long ptrdiff_t;
#else
#error "unknown compiler - please adapt basic types"
#endif

/* bool type */
#ifndef __cplusplus
#define true 1
#define false 0
#define bool _Bool
#endif

#define OE_SCHAR_MIN (-128)
#define OE_SCHAR_MAX 127
#define OE_UCHAR_MAX 255
#define OE_CHAR_MIN (-128)
#define OE_CHAR_MAX 127
#define OE_CHAR_BIT 8
#define OE_SHRT_MIN (-1 - 0x7fff)
#define OE_SHRT_MAX 0x7fff
#define OE_USHRT_MAX 0xffff
#define OE_INT_MIN (-1 - 0x7fffffff)
#define OE_INT_MAX 0x7fffffff
#define OE_UINT_MAX 0xffffffffU
#define OE_LONG_MAX 0x7fffffffffffffffL
#define OE_LONG_MIN (-OE_LONG_MAX - 1)
#define OE_ULONG_MAX (2UL * OE_LONG_MAX + 1)
#define OE_LLONG_MAX 0x7fffffffffffffffLL
#define OE_LLONG_MIN (-OE_LLONG_MAX - 1)
#define OE_ULLONG_MAX (2ULL * OE_LLONG_MAX + 1)

#define OE_INT8_MIN (-1 - 0x7f)
#define OE_INT8_MAX (0x7f)
#define OE_UINT8_MAX (0xff)
#define OE_INT16_MIN (-1 - 0x7fff)
#define OE_INT16_MAX (0x7fff)
#define OE_UINT16_MAX (0xffff)
#define OE_INT32_MIN (-1 - 0x7fffffff)
#define OE_INT32_MAX (0x7fffffff)
#define OE_UINT32_MAX (0xffffffffu)
#define OE_INT64_MIN (-1 - 0x7fffffffffffffff)
#define OE_INT64_MAX (0x7fffffffffffffff)
#define OE_UINT64_MAX (0xffffffffffffffffu)
#define OE_SIZE_MAX OE_UINT64_MAX

/**
 * This enumeration defines values for the **enclave_type** parameter
 * passed to **oe_create_enclave()**.
 */
typedef enum _oe_enclave_type {
    OE_ENCLAVE_TYPE_UNDEFINED,
    OE_ENCLAVE_TYPE_SGX,
    OE_ENCLAVE_TYPE_TRUSTZONE,
    __OE_ENCLAVE_TYPE_MAX = OE_ENUM_MAX,
} oe_enclave_type_t;

/**
 * This is an opaque handle to an enclave returned by oe_create_enclave().
 * This definition is shared by the enclave and the host.
 */
typedef struct _oe_enclave oe_enclave_t;

/**
 * This enumeration type defines the policy used to derive a seal key.
 */
typedef enum _oe_seal_policy {
    /**
     * Key is derived from a measurement of the enclave. Under this policy,
     * the sealed secret can only be unsealed by an instance of the exact
     * enclave code that sealed it.
     */
    OE_SEAL_POLICY_UNIQUE = 1,
    /**
     * Key is derived from the signer of the enclave. Under this policy,
     * the sealed secret can be unsealed by any enclave signed by the same
     * signer as that of the sealing enclave.
     */
    OE_SEAL_POLICY_PRODUCT = 2,
    /**
     * Unused.
     */
    _OE_SEAL_POLICY_MAX = OE_ENUM_MAX,
} oe_seal_policy_t;
```

##### 1.7.1.8 openenclave/bits/safecrt.h
```
oe_result_t oe_memcpy_s(
    void* dst,
    size_t dst_size,
    const void* src,
    size_t num_bytes);

oe_result_t oe_memmove_s(
    void* dst,
    size_t dst_size,
    const void* src,
    size_t num_bytes);

oe_result_t oe_memset_s(
    void* dst,
    size_t dst_size,
    int value,
    size_t num_bytes);

oe_result_t oe_strncat_s(
    char* dst,
    size_t dst_size,
    const char* src,
    size_t num_bytes);

oe_result_t oe_strncpy_s(
    char* dst,
    size_t dst_size,
    const char* src,
    size_t num_bytes);
```

##### 1.7.1.9 openenclave/bits/safemath.h
This header provides safe arithmetic functions for adding, subtracting and multiplying 8/16/32/64 bit signed/unsigned integers. These functions return 'OE_INTEGER_OVERFLOW' if overflow is detected and 'OE_OK' otherwise.
```
/* Some compilers don't have __has_builtin like MSVC. */
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif /* __has_builtin */

#if __has_builtin(__builtin_add_overflow)
#define SAFE_ADD(a, b, c, minz, maxz) \
    return __builtin_add_overflow(a, b, c) ? OE_INTEGER_OVERFLOW : OE_OK;
#else
/*
 * Two cases for addition:
 * - (b > 0): a + b overflows if a + b > MAX, so check a > MAX - b.
 * - (b < 0): a + b overflows if a + b < MIN, so check a < MIN - b.
 * Note that the unsigned case is handled by the (b > 0) case.
 */
#define SAFE_ADD(a, b, c, minz, maxz)      \
    do                                     \
    {                                      \
        if ((b) > 0 && (a) > (maxz) - (b)) \
            return OE_INTEGER_OVERFLOW;    \
        if ((b) < 0 && (a) < (minz) - (b)) \
            return OE_INTEGER_OVERFLOW;    \
        *(c) = (a) + (b);                  \
        return OE_OK;                      \
    } while (0);
#endif /* __has_builtin(__builtin_add_overflow) */

#if __has_builtin(__builtin_sub_overflow)
#define SAFE_SUBTRACT(a, b, c, minz, maxz) \
    return __builtin_sub_overflow(a, b, c) ? OE_INTEGER_OVERFLOW : OE_OK;
#else
/*
 * Two cases for subtraction:
 * - (b > 0): a - b overflows if a - b < MIN, so check a < MIN + b.
 * - (b < 0): a - b overflows if a - b > MAX, so check a > MAX + b.
 * Note that the unsigned case is handled by the (b > 0) case with MIN = 0.
 */
#define SAFE_SUBTRACT(a, b, c, minz, maxz) \
    do                                     \
    {                                      \
        if ((b) > 0 && (a) < (minz) + (b)) \
            return OE_INTEGER_OVERFLOW;    \
        if ((b) < 0 && (a) > (maxz) + (b)) \
            return OE_INTEGER_OVERFLOW;    \
        *(c) = (a) - (b);                  \
        return OE_OK;                      \
    } while (0);
#endif /* __has_builtin(__builtin_sub_overflow) */

#if __has_builtin(__builtin_mul_overflow)
#define SAFE_MULTIPLY(a, b, c, minz, maxz) \
    return __builtin_mul_overflow(a, b, c) ? OE_INTEGER_OVERFLOW : OE_OK;
#else
/*
 * Four cases for multiply:
 * - (a > 0, b > 0): a * b overflows if a * b > MAX, so check a > MAX / b.
 * - (a > 0, b < 0): a * b overflows if a * b < MIN, so check b < MIN / a.
 * - (a < 0, b > 0): a * b overflows if a * b < MIN, so check a < MIN / b.
 * - (a < 0, b < 0): a * b overflows if a * b > MAX, so check a < MAX / b.
 * Note that the unsigned case is handled by the (a > 0, b > 0) case.
 *
 * For the (a > 0, b < 0) case, we purposely do MIN / a instead of
 * MIN / b, since MIN / b produces an integer overflow if b == -1.
 */
#define SAFE_MULTIPLY(a, b, c, minz, maxz)  \
    do                                      \
    {                                       \
        if ((a) > 0 && (b) > 0)             \
        {                                   \
            if ((a) > (maxz) / (b))         \
                return OE_INTEGER_OVERFLOW; \
        }                                   \
        else if ((a) > 0 && (b) < 0)        \
        {                                   \
            if ((b) < (minz) / (a))         \
                return OE_INTEGER_OVERFLOW; \
        }                                   \
        else if ((a) < 0 && (b) > 0)        \
        {                                   \
            if ((a) < (minz) / (b))         \
                return OE_INTEGER_OVERFLOW; \
        }                                   \
        else if ((a) < 0 && (b) < 0)        \
        {                                   \
            if ((a) < (maxz) / (b))         \
                return OE_INTEGER_OVERFLOW; \
        }                                   \
        *(c) = (a) * (b);                   \
        return OE_OK;                       \
    } while (0);
#endif /* __has_builtin(__builtin_mul_overflow) */

/* Safe addition methods. */
OE_INLINE oe_result_t oe_safe_add_s8(int8_t a, int8_t b, int8_t* c)
{
    SAFE_ADD(a, b, c, OE_INT8_MIN, OE_INT8_MAX);
}

OE_INLINE oe_result_t oe_safe_add_u8(uint8_t a, uint8_t b, uint8_t* c)
{
    SAFE_ADD(a, b, c, 0, OE_UINT8_MAX);
}

OE_INLINE oe_result_t oe_safe_add_s16(int16_t a, int16_t b, int16_t* c)
{
    SAFE_ADD(a, b, c, OE_INT16_MIN, OE_INT16_MAX);
}

OE_INLINE oe_result_t oe_safe_add_u16(uint16_t a, uint16_t b, uint16_t* c)
{
    SAFE_ADD(a, b, c, 0, OE_UINT16_MAX);
}

OE_INLINE oe_result_t oe_safe_add_s32(int32_t a, int32_t b, int32_t* c)
{
    SAFE_ADD(a, b, c, OE_INT32_MIN, OE_INT32_MAX);
}

OE_INLINE oe_result_t oe_safe_add_u32(uint32_t a, uint32_t b, uint32_t* c)
{
    SAFE_ADD(a, b, c, 0, OE_UINT32_MAX);
}

OE_INLINE oe_result_t oe_safe_add_s64(int64_t a, int64_t b, int64_t* c)
{
    SAFE_ADD(a, b, c, OE_INT64_MIN, OE_INT64_MAX);
}

OE_INLINE oe_result_t oe_safe_add_u64(uint64_t a, uint64_t b, uint64_t* c)
{
    SAFE_ADD(a, b, c, 0, OE_UINT64_MAX);
}

OE_INLINE oe_result_t oe_safe_add_sizet(size_t a, size_t b, size_t* c)
{
    SAFE_ADD(a, b, c, 0, OE_SIZE_MAX);
}

/* Safe subtraction methods. */
OE_INLINE oe_result_t oe_safe_sub_s8(int8_t a, int8_t b, int8_t* c)
{
    SAFE_SUBTRACT(a, b, c, OE_INT8_MIN, OE_INT8_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_u8(uint8_t a, uint8_t b, uint8_t* c)
{
    SAFE_SUBTRACT(a, b, c, 0, OE_UINT8_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_s16(int16_t a, int16_t b, int16_t* c)
{
    SAFE_SUBTRACT(a, b, c, OE_INT16_MIN, OE_INT16_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_u16(uint16_t a, uint16_t b, uint16_t* c)
{
    SAFE_SUBTRACT(a, b, c, 0, OE_UINT16_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_s32(int32_t a, int32_t b, int32_t* c)
{
    SAFE_SUBTRACT(a, b, c, OE_INT32_MIN, OE_INT32_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_u32(uint32_t a, uint32_t b, uint32_t* c)
{
    SAFE_SUBTRACT(a, b, c, 0, OE_UINT32_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_s64(int64_t a, int64_t b, int64_t* c)
{
    SAFE_SUBTRACT(a, b, c, OE_INT64_MIN, OE_INT64_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_u64(uint64_t a, uint64_t b, uint64_t* c)
{
    SAFE_SUBTRACT(a, b, c, 0, OE_UINT64_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_sizet(size_t a, size_t b, size_t* c)
{
    SAFE_SUBTRACT(a, b, c, 0, OE_SIZE_MAX);
}

/* Safe multiplication methods. */
OE_INLINE oe_result_t oe_safe_mul_s8(int8_t a, int8_t b, int8_t* c)
{
    SAFE_MULTIPLY(a, b, c, OE_INT8_MIN, OE_INT8_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_u8(uint8_t a, uint8_t b, uint8_t* c)
{
    SAFE_MULTIPLY(a, b, c, 0, OE_UINT8_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_s16(int16_t a, int16_t b, int16_t* c)
{
    SAFE_MULTIPLY(a, b, c, OE_INT16_MIN, OE_INT16_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_u16(uint16_t a, uint16_t b, uint16_t* c)
{
    SAFE_MULTIPLY(a, b, c, 0, OE_UINT16_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_s32(int32_t a, int32_t b, int32_t* c)
{
    SAFE_MULTIPLY(a, b, c, OE_INT32_MIN, OE_INT32_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_u32(uint32_t a, uint32_t b, uint32_t* c)
{
    SAFE_MULTIPLY(a, b, c, 0, OE_UINT32_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_s64(int64_t a, int64_t b, int64_t* c)
{
    SAFE_MULTIPLY(a, b, c, OE_INT64_MIN, OE_INT64_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_u64(uint64_t a, uint64_t b, uint64_t* c)
{
    SAFE_MULTIPLY(a, b, c, 0, OE_UINT64_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_sizet(size_t a, size_t b, size_t* c)
{
    SAFE_MULTIPLY(a, b, c, 0, OE_SIZE_MAX);
```

#### 1.7.2 Host APIs
The following APIs are exposed to normal applications.

##### 1.7.2.1 openenclave/host.h
```
/**
 *  Flag passed into oe_create_enclave to run the enclave in debug mode.
 *  The flag allows the enclave to be created without the enclave binary
 *  being signed. It also gives a developer permission to debug the process
 *  and get access to enclave memory. What this means is ** DO NOT SHIP
 *  CODE WITH THE OE_ENCLAVE_FLAG_DEBUG ** because it is unsecure. What
 *  it does give is the ability to develop your enclave more easily. Before
 *  you ship the code you need to have a proper code signing story for the
 *  enclave shared library.
 */
#define OE_ENCLAVE_FLAG_DEBUG 0x00000001

/**
 *  Flag passed into oe_create_enclave to run the enclave in simulation mode.
 */
#define OE_ENCLAVE_FLAG_SIMULATE 0x00000002

/**
 *  Flag passed into oe_create_enclave to serialize all ECALLs.
 */
#define OE_ENCLAVE_FLAG_SERIALIZE_ECALLS 0x00000004

/**
 * @cond DEV
 */
#define OE_ENCLAVE_FLAG_RESERVED \
    (~(OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE))
/**
 * @endcond
 */

/**
 * Type of each function in an ocall-table.
 */
typedef void (*oe_ocall_func_t)(void*);

/**
 * Create an enclave from an enclave image file.
 *
 * This function creates an enclave from an enclave image file. On successful
 * return, the enclave is fully initialized and ready to use.
 *
 * @param path The path of an enclave image file in ELF-64 format. This
 * file must have been linked with the **oecore** library and signed by the
 * **oesign** tool.
 *
 * @param type The type of enclave supported by the enclave image file.
 *     - 0 - Automatically detect based on processor
 *     - non-zero - An enclave of the specified type
 *
 * @param flags These flags control how the enclave is run.
 *     It is the bitwise OR of zero or more of the following flags
 *     - OE_ENCLAVE_FLAG_SIMULATE - runs the enclave in simulation mode
 *     - OE_ENCLAVE_FLAG_DEBUG - runs the enclave in debug mode.
 *                               DO NOT SHIP CODE with this flag
 *
 * @param config Additional enclave creation configuration data for the specific
 * enclave type. This parameter is reserved and must be NULL.
 *
 * @param config_size The size of the **config** data buffer in bytes.
 *
 * @param ocall_table Pointer to table of ocall functions generated by
 * oeedger8r.
 *
 * @param ocall_table_size The size of the **ocall_table**.
 *
 * @param enclave This points to the enclave instance upon success.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_create_enclave(
    const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    const void* config,
    uint32_t config_size,
    const oe_ocall_func_t* ocall_table,
    uint32_t ocall_table_size,
    oe_enclave_t** enclave);

/**
 * Terminate an enclave and reclaims its resources.
 *
 * This function terminates an enclave and reclaims its resources. This
 * involves unmapping the memory that was mapped by **oe_create_enclave()**.
 * Once this is performed, the enclave can no longer be accessed.
 *
 * @param enclave The instance of the enclave to be terminated.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_terminate_enclave(oe_enclave_t* enclave);

/**
 * Perform a high-level enclave function call (ECALL).
 *
 * Call the enclave function whose name is given by the **func** parameter.
 * The enclave must define a corresponding function with the following
 * prototype.
 *
 *     OE_ECALL void (*)(void* args);
 *
 * The meaning of the **args** parameter is defined by the implementer of the
 * function and may be null.
 *
 * This function is implemented using the low-level oe_ecall() interface
 * where the function number is given by the **OE_ECALL_CALL_ENCLAVE** constant.
 *
 * Note that the return value of this function only indicates the success of
 * the call and not of the underlying function. The ECALL implementation must
 * define its own error reporting scheme based on **args**.
 *
 * @deprecated This function is deprecated. Use oeedger8r to generate
 * code that will call oe_call_enclave_function() instead.
 *
 * @param enclave The instance of the enclave to be called.
 *
 * @param func The name of the enclave function that will be called.
 *
 * @param args The arguments to be passed to the enclave function.
 *
 * @returns This function return **OE_OK** on success.
 *
 */
OE_DEPRECATED(oe_result_t oe_call_enclave(
    oe_enclave_t* enclave,
    const char* func,
    void* args),
    "This function is deprecated. Use oeedger8r to generate code that will call oe_call_enclave_function() instead.");

#if (OE_API_VERSION < 2)
#define oe_get_report      oe_get_report_v1
#define oe_get_target_info oe_get_target_info_v1
#else
#define oe_get_report      oe_get_report_v2
#define oe_get_target_info oe_get_target_info_v2
#endif

/**
 * Get a report signed by the enclave platform for use in attestation.
 *
 * This function creates a report to be used in local or remote attestation.
 *
 * If the *report_buffer* is NULL or *report_size* parameter is too small,
 * this function returns OE_BUFFER_TOO_SMALL.
 *
 * @deprecated This function is deprecated. Use oe_get_report_v2() instead.
 *
 * @param enclave The instance of the enclave that will generate the report.
 * @param flags Specifying default value (0) generates a report for local
 * attestation. Specifying OE_REPORT_FLAGS_REMOTE_ATTESTATION generates a
 * report for remote attestation.
 * @param opt_params Optional additional parameters needed for the current
 * enclave type. For SGX, this can be sgx_target_info_t for local attestation.
 * @param opt_params_size The size of the **opt_params** buffer.
 * @param report_buffer The buffer to where the resulting report will be copied.
 * @param report_buffer_size The size of the **report** buffer. This is set to
 * the
 * required size of the report buffer on return.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUFFER_TOO_SMALL The **report_buffer** buffer is NULL or too
 * small.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
OE_DEPRECATED(oe_result_t oe_get_report_v1(
    oe_enclave_t* enclave,
    uint32_t flags,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report_buffer,
    size_t* report_buffer_size),
    "This function is deprecated. Use oe_get_report_v2() instead.");

/**
 * Get a report signed by the enclave platform for use in attestation.
 *
 * This function creates a report to be used in local or remote attestation.
 *
 * @param[in] enclave The instance of the enclave that will generate the report.
 * @param[in] flags Specifying default value (0) generates a report for local
 * attestation. Specifying OE_REPORT_FLAGS_REMOTE_ATTESTATION generates a
 * report for remote attestation.
 * @param[in] opt_params Optional additional parameters needed for the current
 * enclave type. For SGX, this can be sgx_target_info_t for local attestation.
 * @param[in] opt_params_size The size of the **opt_params** buffer.
 * @param[out] report_buffer This points to the resulting report upon success.
 * @param[out] report_buffer_size This is set to the size of the report buffer
 * on success.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
* @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
oe_result_t oe_get_report_v2(
    oe_enclave_t* enclave,
    uint32_t flags,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size);

/**
 * Frees a report buffer obtained from oe_get_report.
 *
 * @param[in] report_buffer The report buffer to free.
 */
void oe_free_report(uint8_t* report_buffer);

/**
 * Extracts additional platform specific data from the report and writes
 * it to *target_info_buffer*. After calling this function, the
 * *target_info_buffer* can used for the *opt_params* field in *oe_get_report*.
 *
 * For example, on SGX, the *target_info_buffer* can be used as a
 * sgx_target_info_t for local attestation.
 *
 * If the *target_info_buffer* is NULL or the *target_info_size* parameter is
 * too small, this function returns OE_BUFFER_TOO_SMALL.
 *
 * @deprecated This function is deprecated. Use oe_get_target_info_v2() instead.
 *
 * @param report The report returned by **oe_get_report**.
 * @param report_size The size of **report** in bytes.
 * @param target_info_buffer The buffer to where the platform specific data
 * will be placed.
 * @param target_info_size The size of **target_info_buffer**. This is set to
 * the required size of **target_info_buffer** on return.
 *
 * @retval OE_OK The platform specific data was successfully extracted.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUFFER_TOO_SMALL **target_info_buffer** is NULL or too small.
 *
 */
OE_DEPRECATED(oe_result_t oe_get_target_info_v1(
    const uint8_t* report,
    size_t report_size,
    void* target_info_buffer,
    size_t* target_info_size),
    "This function is deprecated. Use oe_get_target_info_v2() instead.");

/**
 * Extracts additional platform specific data from the report and writes
 * it to *target_info_buffer*. After calling this function, the
 * *target_info_buffer* can used for the *opt_params* field in *oe_get_report*.
 *
 * For example, on SGX, the *target_info_buffer* can be used as a
 * sgx_target_info_t for local attestation.
 *
 * If the *target_info_buffer* is NULL or the *target_info_size* parameter is
 * too small, this function returns OE_BUFFER_TOO_SMALL.
 *
 * @param[in] report The report returned by **oe_get_report**.
 * @param[in] report_size The size of **report** in bytes.
 * @param[out] target_info_buffer This points to the platform specific data
 * upon success.
 * @param[out] target_info_size This is set to
 * the size of **target_info_buffer** on success.
 *
 * @retval OE_OK The platform specific data was successfully extracted.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
oe_result_t oe_get_target_info_v2(
    const uint8_t* report,
    size_t report_size,
    void** target_info_buffer,
    size_t* target_info_size);

/**
 * Frees a target info obtained from oe_get_target_info.
 *
 * @param[in] target_info_buffer The target info to free.
 */
void oe_free_target_info(
    void* target_info_buffer);

/**
 * Parse an enclave report into a standard format for reading.
 *
 * @param report The buffer containing the report to parse.
 * @param report_size The size of the **report** buffer.
 * @param parsed_report The **oe_report_t** structure to populate with the
 * report
 * properties in a standard format. The *parsed_report* holds pointers to fields
 * within the supplied *report* and must not be used beyond the lifetime of the
 * *report*.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 */
oe_result_t oe_parse_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);

/**
 * Verify the integrity of the report and its signature.
 *
 * This function verifies that the report signature is valid. If the report is
 * local, it verifies that it is correctly signed by the enclave
 * platform. If the report is remote, it verifies that the signing authority is
 * rooted to a trusted authority such as the enclave platform manufacturer.
 *
 * @param enclave The instance of the enclave that will be used to
 * verify a local report. For remote reports, this parameter can be NULL.
 * @param report The buffer containing the report to verify.
 * @param report_size The size of the **report** buffer.
 * @param parsed_report Optional **oe_report_t** structure to populate with the
 * report properties in a standard format.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_verify_report(
    oe_enclave_t* enclave,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);

/**
 * Gets the public key of an enclave.
 *
 * @param[in] enclave The instance of the enclave that will be used.
 * @param[in] seal_policy The seal policy used to determine which key to get.
 * @param[out] key_buffer Upon success, this points to the public key.
 * @param[out] key_buffer_size Upon success, this contains the size of the *key_buffer* buffer.
 * @param[out] key_info Reserved for future use.  Must pass NULL.
 * @param[out] key_info_size Reserved for future use.  Must pass NULL.
 *
 * @retval OE_OK The public key was successfully obtained.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 */
oe_result_t oe_get_public_key_by_policy(
    oe_enclave_t* enclave,
    oe_seal_policy_t seal_policy,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size);

/**
 * Frees a public key.
 *
 * @param[in] key_buffer If non-NULL, frees the key buffer.
 * @param[in] key_info If non-NULL, frees the key info.
 */
void oe_free_public_key(
    uint8_t* key_buffer,
    uint8_t* key_info);
```

#### 1.7.3 TEE APIs
The following APIs are exposed to code that runs in a TEE.

##### 1.7.3.1 openenclave/enclave.h
```
/**
 * Register a new vectored exception handler.
 *
 * Call this function to add a new vectored exception handler. If successful,
 * the registered handler will be called when an exception happens inside the
 * enclave.
 *
 * @param is_first_handler The parameter indicates that the input handler should
 * be the first exception handler to be called. If it is false, the input
 * handler will be appended to the end of exception handler chain, otherwise
 * it will be added as the first handler in the exception handler chain.
 * @param vectored_handler The input vectored exception handler to register. It
 * must be a function defined in the enclave. The same handler can only be
 * registered once; a 2nd registration will fail. If the function succeeds, the
 * handler may be removed later by passing it to
 * oe_remove_vectored_exception_handler().
 *
 * @returns OE_OK successful
 * @returns OE_INVALID_PARAMETER a parameter is invalid
 * @returns OE_FAILURE failed to add handler
*/
oe_result_t oe_add_vectored_exception_handler(
    bool is_first_handler,
    oe_vectored_exception_handler_t vectored_handler);

/**
* Remove an existing vectored exception handler.
*
* @param vectored_handler The pointer to a registered exception handler returned
* from a successful oe_add_vectored_exception_handler() call.
*
* @returns OE_OK success
* @returns OE_INVALID_PARAMETER a parameter is invalid
* @returns OE_FAILURE failed to remove handler
*/
oe_result_t oe_remove_vectored_exception_handler(
    oe_vectored_exception_handler_t vectored_handler);

/**
 * Perform a high-level enclave function call (OCALL).
 *
 * Call the host function whose name is given by the **func** parameter.
 * The host must define a corresponding function with the following
 * prototype.
 *
 *     OE_OCALL void (*)(void* args);
 *
 * The meaning of the **args** parameter is defined by the implementer of the
 * function and may be null.
 *
 * Note that the return value of this function only indicates the success of
 * the call and not of the underlying function. The OCALL implementation must
 * define its own error reporting scheme based on **args**.
 *
 * While handling the OCALL, the host is not allowed to make an ECALL back into
 * the enclave. A re-entrant ECALL will fail and return OE_REENTRANT_ECALL.
 *
 * @deprecated This function has been deprecated. Use oeedger8r to generate
 * code that will call oe_call_host_function() instead.
 *
 * @param func The name of the enclave function that will be called.
 * @param args The arguments to be passed to the enclave function.
 *
 * @returns This function return **OE_OK** on success.
 *
 */
OE_DEPRECATED(oe_result_t oe_call_host(const char* func, void* args),
              "This function is deprecated. Use oeedger8r to generate code that will call oe_call_host_function() instead.");
/**
 * Perform a high-level host function call (OCALL).
 *
 * Call the host function whose address is given by the **func** parameter,
 * which is the address of a function defined in the host with the following
 * prototoype.
 *
 *     OE_OCALL void (*)(void* args);
 *
 * The meaning of the **args** parameter is defined by the implementer of the
 * function and may be null.
 *
 * Note that the return value of this function only indicates the success of
 * the call and not of the underlying function. The OCALL implementation must
 * define its own error reporting scheme based on **args**.
 *
 * @deprecated This function is deprecated. Use oeedger8r to generate code that
 * will call oe_call_host_function() instead.
 *
 * @param func The address of the host function that will be called.
 * @param args The arguments to be passed to the host function.
 *
 * @return OE_OK the call was successful.
 * @return OE_INVALID_PARAMETER a parameter is invalid.
 * @return OE_FAILURE the call failed.
 */
OE_DEPRECATED(oe_result_t oe_call_host_by_address(
    void (*func)(void*, oe_enclave_t*),
    void* args),
    "This function is deprecated. Use oeedger8r to generate code that will call oe_call_host_function() instead.");

/**
 * Check whether the given buffer is strictly within the enclave.
 *
 * Check whether the buffer given by the **ptr** and **size** parameters is
 * strictly within the enclave's memory. If so, return true. If any
 * portion of the buffer lies outside the enclave's memory, return false.
 *
 * @param ptr The pointer pointer to buffer.
 * @param size The size of buffer
 *
 * @retval true The buffer is strictly within the enclave.
 * @retval false At least some part of the buffer is outside the enclave, or
 * the arguments are invalid. For example, if **ptr** is null or **size**
 * causes arithmetic operations to wrap.
 *
 */
bool oe_is_within_enclave(const void* ptr, size_t size);

/**
 * Check whether the given buffer is strictly outside the enclave.
 *
 * Check whether the buffer given by the **ptr** and **size** parameters is
 * strictly outside the enclave's memory. If so, return true. If any
 * portion of the buffer lies within the enclave's memory, return false.
 *
 * @param ptr The pointer to buffer.
 * @param size The size of buffer.
 *
 * @retval true The buffer is strictly outside the enclave.
 * @retval false At least some part of the buffer is inside the enclave, or
 * the arguments are invalid. For example, if **ptr** is null or **size**
 * causes arithmetic operations to wrap.
 *
 */
bool oe_is_outside_enclave(const void* ptr, size_t size);

/**
 * Allocate bytes from the host's heap.
 *
 * This function allocates **size** bytes from the host's heap and returns the
 * address of the allocated memory. The implementation performs an OCALL to
 * the host, which calls malloc(). To free the memory, it must be passed to
 * oe_host_free().
 *
 * @param size The number of bytes to be allocated.
 *
 * @returns The allocated memory or NULL if unable to allocate the memory.
 *
 */
void* oe_host_malloc(size_t size);

/**
 * Reallocate bytes from the host's heap.
 *
 * This function changes the size of the memory block pointed to by **ptr**
 * on the host's heap to **size** bytes. The memory block may be moved to a
 * new location, which is returned by this function. The implementation
 * performs an OCALL to the host, which calls realloc(). To free the memory,
 * it must be passed to oe_host_free().
 *
 * @param ptr The memory block to change the size of. If NULL, this method
 * allocates **size** bytes as if oe_host_malloc was invoked. If not NULL,
 * it should be a pointer returned by a previous call to oe_host_calloc,
 * oe_host_malloc or oe_host_realloc.
 * @param size The number of bytes to be allocated. If 0, this method
 * deallocates the memory at **ptr**. If the new size is larger, the value
 * of the memory in the new allocated range is indeterminate.
 *
 * @returns The pointer to the reallocated memory or NULL if **ptr** was
 * freed by setting **size** to 0. This method also returns NULL if it was
 * unable to reallocate the memory, in which case the original **ptr**
 * remains valid and its contents are unchanged.
 *
 */
void* oe_host_realloc(void* ptr, size_t size);

/**
 * Allocate zero-filled bytes from the host's heap.
 *
 * This function allocates **size** bytes from the host's heap and fills it
 * with zero character. It returns the address of the allocated memory. The
 * implementation performs an OCALL to the host, which calls calloc().
 * To free the memory, it must be passed to oe_host_free().
 *
 * @param nmemb The number of elements to be allocated and zero-filled.
 * @param size The size of each element.
 *
 * @returns The allocated memory or NULL if unable to allocate the memory.
 *
 */
void* oe_host_calloc(size_t nmemb, size_t size);

/**
 * Release allocated memory.
 *
 * This function releases memory allocated with oe_host_malloc() or
 * oe_host_calloc() by performing an OCALL where the host calls free().
 *
 * @param ptr Pointer to memory to be released or null.
 *
 */
void oe_host_free(void* ptr);

/**
 * Make a heap copy of a string.
 *
 * This function allocates memory on the host's heap, copies no more than
 * *n* bytes from the **str** parameter to that memory, and returns a pointer
 * to the newly allocated memory.
 *
 * @param str The string to be copied.
 * @param n The number of characters to be copied.
 *
 * @returns A pointer to the newly allocated string or NULL if unable to
 * allocate the storage.
 */
char* oe_host_strndup(const char* str, size_t n);

/**
 * Abort execution of the enclave.
 *
 * Mark the enclave as aborting. This blocks future enclave entry calls. The
 * enclave continues to execute until all threads exit the enclave.
 */
void oe_abort(void);

/**
 * Called whenever an assertion fails.
 *
 * This internal function is called when the expression of the oe_assert()
 * macro evaluates to zero. For example:
 *
 *     oe_assert(x > y);
 *
 * If the expression evaluates to zero, this function is called with the
 * string representation of the expression as well as the file, the line, and
 * the function name where the macro was expanded.
 *
 * The __oe_assert_fail() function performs a host call to print a message
 * and then calls oe_abort().
 *
 * @param expr The argument of the oe_assert() macro.
 * @param file The name of the file where oe_assert() was invoked.
 * @param line The line number where oe_assert() was invoked.
 * @param func The name of the function that invoked oe_assert().
 *
 */
void __oe_assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* func);

/**
 * Evaluates assertion.
 */
#ifndef NDEBUG
#define oe_assert(EXPR)                                                \
    do                                                                 \
    {                                                                  \
        if (!(EXPR))                                                   \
            __oe_assert_fail(#EXPR, __FILE__, __LINE__, __FUNCTION__); \
    } while (0)
#else
#define oe_assert(EXPR)
#endif

#if (OE_API_VERSION < 2)
#define oe_get_report             oe_get_report_v1
#define oe_get_target_info        oe_get_target_info_v1
#define oe_get_seal_key_by_policy oe_get_seal_key_by_policy_v1
#define oe_get_seal_key           oe_get_seal_key_v1

#else
#define oe_get_report             oe_get_report_v2
#define oe_get_target_info        oe_get_target_info_v2
#define oe_get_seal_key_by_policy oe_get_seal_key_by_policy_v2
#define oe_get_seal_key           oe_get_seal_key_v2
#endif

/**
 * Get a report signed by the enclave platform for use in attestation.
 *
 * This function creates a report to be used in local or remote attestation. The
 * report shall contain the data given by the **report_data** parameter.
 *
 * If the *report_buffer* is NULL or *report_size* parameter is too small,
 * this function returns OE_BUFFER_TOO_SMALL.
 *
 * @deprecated This function is deprecated. Use oe_get_report_v2() instead.
 *
 * @param flags Specifying default value (0) generates a report for local
 * attestation. Specifying OE_REPORT_FLAGS_REMOTE_ATTESTATION generates a
 * report for remote attestation.
 * @param report_data The report data that will be included in the report.
 * @param report_data_size The size of the **report_data** in bytes.
 * @param opt_params Optional additional parameters needed for the current
 * enclave type. For SGX, this can be sgx_target_info_t for local attestation.
 * @param opt_params_size The size of the **opt_params** buffer.
 * @param report_buffer The buffer to where the resulting report will be copied.
 * @param report_buffer_size The size of the **report** buffer. This is set to
 * the
 * required size of the report buffer on return.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUFFER_TOO_SMALL The **report_buffer** buffer is NULL or too
 * small.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
OE_DEPRECATED(oe_result_t oe_get_report_v1(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report_buffer,
    size_t* report_buffer_size),
    "This function is deprecated. Use oe_get_report_v2() instead.");

/**
 * Get a report signed by the enclave platform for use in attestation.
 *
 * This function creates a report to be used in local or remote attestation. The
 * report shall contain the data given by the **report_data** parameter.
 *
 * @param[in] flags Specifying default value (0) generates a report for local
 * attestation. Specifying OE_REPORT_FLAGS_REMOTE_ATTESTATION generates a
 * report for remote attestation.
 * @param[in] report_data The report data that will be included in the report.
 * @param[in] report_data_size The size of the **report_data** in bytes.
 * @param[in] opt_params Optional additional parameters needed for the current
 * enclave type. For SGX, this can be sgx_target_info_t for local attestation.
 * @param[in] opt_params_size The size of the **opt_params** buffer.
 * @param[out] report_buffer This points to the resulting report upon success.
 * @param[out] report_buffer_size This is set to the
 * size of the report buffer on success.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
oe_result_t oe_get_report_v2(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size);

/**
 * Frees a report buffer obtained from oe_get_report.
 *
 * @param[in] report_buffer The report buffer to free.
 */
void oe_free_report(uint8_t* report_buffer);

/**
 * Extracts additional platform specific data from the report and writes
 * it to *target_info_buffer*. After calling this function, the
 * *target_info_buffer* can used for the *opt_params* field in *oe_get_report*.
 *
 * For example, on SGX, the *target_info_buffer* can be used as a
 * sgx_target_info_t for local attestation.
 *
 * If the *target_info_buffer* is NULL or the *target_info_size* parameter is
 * too small, this function returns OE_BUFFER_TOO_SMALL.
 *
 * @deprecated This function is deprecated. Use oe_get_target_info_v2() instead.
 *
 * @param report The report returned by **oe_get_report**.
 * @param report_size The size of **report** in bytes.
 * @param target_info_buffer The buffer to where the platform specific data
 * will be placed.
 * @param target_info_size The size of **target_info_buffer**. This is set to
 * the required size of **target_info_buffer** on return.
 *
 * @retval OE_OK The platform specific data was successfully extracted.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUFFER_TOO_SMALL **target_info_buffer** is NULL or too small.
 *
 */
OE_DEPRECATED(oe_result_t oe_get_target_info_v1(
    const uint8_t* report,
    size_t report_size,
    void* target_info_buffer,
    size_t* target_info_size),
    "This function is deprecated. Use oe_get_target_info_v2() instead.");

/**
 * Extracts additional platform specific data from the report and writes
 * it to *target_info_buffer*. After calling this function, the
 * *target_info_buffer* can used for the *opt_params* field in *oe_get_report*.
 *
 * For example, on SGX, the *target_info_buffer* can be used as a
 * sgx_target_info_t for local attestation.
*
 * @param[in] report The report returned by **oe_get_report**.
 * @param[in] report_size The size of **report** in bytes.
 * @param[out] target_info_buffer This points to the platform specific data
 * upon success.
 * @param[out] target_info_size This is set to
 * the size of **target_info_buffer** on success.
 *
 * @retval OE_OK The platform specific data was successfully extracted.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
oe_result_t oe_get_target_info_v2(
    const uint8_t* report,
    size_t report_size,
    void** target_info_buffer,
    size_t* target_info_size);

/**
 * Frees target info obtained from oe_get_target_info.
 *
 * @param[in] target_info The platform specific data to free.
 *
 */
void oe_free_target_info(void* target_info);

/**
 * Parse an enclave report into a standard format for reading.
 *
 * @param report The buffer containing the report to parse.
 * @param report_size The size of the **report** buffer.
 * @param parsed_report The **oe_report_t** structure to populate with the
 * report
 * properties in a standard format. The *parsed_report* holds pointers to fields
 * within the supplied *report* and must not be used beyond the lifetime of the
 * *report*.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_parse_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);

/**
 * Verify the integrity of the report and its signature.
 *
 * This function verifies that the report signature is valid. If the report is
 * local, it verifies that it is correctly signed by the enclave
 * platform. If the report is remote, it verifies that the signing authority is
 * rooted to a trusted authority such as the enclave platform manufacturer.
 *
 * @param report The buffer containing the report to verify.
 * @param report_size The size of the **report** buffer.
 * @param parsed_report Optional **oe_report_t** structure to populate with the
 * report properties in a standard format.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_verify_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);

/**
 * Get a symmetric encryption key derived from the specified policy and coupled
 * to the enclave platform.
 *
 * @deprecated This function is deprecated. Use oe_get_seal_key_by_policy_v2() instead.
 *
 * @param seal_policy The policy for the identity properties used to derive the
 * seal key.
 * @param key_buffer The buffer to write the resulting seal key to.
 * @param key_buffer_size The size of the **key_buffer** buffer. If this is too
 * small, this function sets it to the required size and returns
 * OE_BUFFER_TOO_SMALL. When this function success, the number of bytes written
 * to key_buffer is set to it.
 * @param key_info Optional buffer for the enclave-specific key information which
 * can be used to retrieve the same key later, on a newer security version.
 * @param key_info_size The size of the **key_info** buffer. If this is too small,
 * this function sets it to the required size and returns OE_BUFFER_TOO_SMALL.
 * When this function success, the number of bytes written to key_info is set to
 * it.
 *
 * @retval OE_OK The seal key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUFFER_TOO_SMALL The **key_buffer** or **key_info** buffer is too
 * small.
 * @retval OE_UNEXPECTED An unexpected error happened.
 */
OE_DEPRECATED(oe_result_t oe_get_seal_key_by_policy_v1(
    oe_seal_policy_t seal_policy,
    uint8_t* key_buffer,
    size_t* key_buffer_size,
    uint8_t* key_info,
    size_t* key_info_size),
    "This function is deprecated. Use oe_get_seal_key_by_policy_v2() instead");

/**
 * Get a symmetric encryption key derived from the specified policy and coupled
 * to the enclave platform.
 *
 * @param[in] seal_policy The policy for the identity properties used to derive the
 * seal key.
 * @param[out] key_buffer This contains the resulting seal key upon success.
 * @param[out] key_buffer_size This contains the size of the **key_buffer** buffer upon success. 
 * @param[out] key_info If non-NULL, then on success this points to the enclave-specific key information which
 * can be used to retrieve the same key later, on a newer security version.
 * @param[out] key_info_size On success, this is the size of the **key_info** buffer.
 *
 * @retval OE_OK The seal key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_UNEXPECTED An unexpected error happened.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 */
oe_result_t oe_get_seal_key_by_policy_v2(
    oe_seal_policy_t seal_policy,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size);

/**
 * Get a symmetric encryption key from the enclave platform using existing key
 * information.
 *
 * @deprecated This function is deprecated. Use oe_get_seal_key_v2() instead.
 *
 * @param key_info The enclave-specific key information to derive the seal key
 * with.
 * @param key_info_size The size of the **key_info** buffer.
 * @param key_buffer The buffer to write the resulting seal key to. It will not
 * be changed if this function fails.
 * @param key_buffer_size The size of the **key_buffer** buffer. If this is too
 * small, this function sets it to the required size and returns
 * OE_BUFFER_TOO_SMALL. When this function success, the number of bytes written
 * to key_buffer is set to it.
 *
 * @retval OE_OK The seal key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUFFER_TOO_SMALL The **key_buffer** buffer is too small.
 * @retval OE_INVALID_CPUSVN **key_info** contains an invalid CPUSVN.
 * @retval OE_INVALID_ISVSVN **key_info** contains an invalid ISVSVN.
 * @retval OE_INVALID_KEYNAME **key_info** contains an invalid KEYNAME.
 */
OE_DEPRECATED(oe_result_t oe_get_seal_key_v1(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t* key_buffer,
    size_t* key_buffer_size),
    "This function is deprecated. Use oe_get_seal_key_v2() instead.");

/**
 * Get a symmetric encryption key from the enclave platform using existing key
 * information.
 *
 * @param key_info The enclave-specific key information to derive the seal key
 * with.
 * @param key_info_size The size of the **key_info** buffer.
 * @param key_buffer Upon success, this points to the resulting seal key, which should be freed with oe_free_key().
 * @param key_buffer_size Upon success, this contains the size of the **key_buffer** buffer, which should be freed with oe_free_key().
 *
 * @retval OE_OK The seal key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_INVALID_CPUSVN **key_info** contains an invalid CPUSVN.
 * @retval OE_INVALID_ISVSVN **key_info** contains an invalid ISVSVN.
 * @retval OE_INVALID_KEYNAME **key_info** contains an invalid KEYNAME.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 */
oe_result_t oe_get_seal_key_v2(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size);

/* Free a key and/or key info.
 *
 * @param[in] key_buffer If non-NULL, the key buffer to free.
 * @param[in] key_info If non-NULL, the key info buffer to free.
 */
void oe_free_key(
    uint8_t* key_buffer,
    uint8_t* key_info); 
/**
 * Obtains the enclave handle.
 *
 * This function returns the enclave handle for the current enclave. The
 * host obtains this handle by calling **oe_create_enclave()**, which
 * passes the enclave handle to the enclave during initialization. The
 * handle is an address inside the host address space.
 *
 * @deprecated This function is deprecated. Host application code should use
 * edger8r generated code instead.
 *
 * @returns the enclave handle.
 */
OE_DEPRECATED(oe_enclave_t* oe_get_enclave(void),
    "This function is deprecated. Host application code should use edger8r generated code instead.");

/**
 * Obtains the public key corresponding to the enclave's private key.
 *
 * @param[in] seal_policy The policy for the identity properties used to derive the
 * key.
 * @param[out] key_buffer On success, contains a pointer to the key, which should be freed with oe_free_key().
 * @param[out] key_buffer_size On success, contains the size in bytes of the key buffer.
 * @param[out] key_info If non-NULL, then on success this points to the enclave-specific key information which
 * can be used to retrieve the same key later, on a newer security version.
 * @param[out] key_info_size On success, this is the size of the **key_info** buffer.
 */
oe_result_t oe_get_public_key_by_policy(
    oe_seal_policy_t seal_policy,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size);

/**
 * Get a public key from the enclave platform using existing key
 * information.
 *
 * @param key_info The enclave-specific key information to derive the public key
 * with.
 * @param key_info_size The size of the **key_info** buffer.
 * @param key_buffer Upon success, this points to the resulting public key, which should be freed with oe_free_key().
 * @param key_buffer_size Upon success, this contains the size of the **key_buffer** buffer, which should be freed with oe_free_key().
 *
 * @retval OE_OK The seal key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_INVALID_CPUSVN **key_info** contains an invalid CPUSVN.
 * @retval OE_INVALID_ISVSVN **key_info** contains an invalid ISVSVN.
 * @retval OE_INVALID_KEYNAME **key_info** contains an invalid KEYNAME.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 */
oe_result_t oe_get_public_key(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size);

/**
 * Obtains a private key specific to the enclave.
 *
 * @param[in] seal_policy The policy for the identity properties used to derive the
 * key.
 * @param[out] key_buffer On success, contains a pointer to the key, which should be freed with oe_free_key().
 * @param[out] key_buffer_size On success, contains the size in bytes of the key buffer.
 * @param[out] key_info If non-NULL, then on success this points to the enclave-specific key information which
 * can be used to retrieve the same key later, on a newer security version.
 * @param[out] key_info_size On success, this is the size of the **key_info** buffer.
 */
oe_result_t oe_get_private_key_by_policy(
    oe_seal_policy_t seal_policy,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size);

/**
 * Get a private key from the enclave platform using existing key
 * information.
 *
 * @param key_info The enclave-specific key information to derive the private key
 * with.
 * @param key_info_size The size of the **key_info** buffer.
 * @param key_buffer Upon success, this points to the resulting private key, which should be freed with oe_free_key().
 * @param key_buffer_size Upon success, this contains the size of the **key_buffer** buffer, which should be freed with oe_free_key().
 *
 * @retval OE_OK The seal key was successfully requested.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_INVALID_CPUSVN **key_info** contains an invalid CPUSVN.
 * @retval OE_INVALID_ISVSVN **key_info** contains an invalid ISVSVN.
 * @retval OE_INVALID_KEYNAME **key_info** contains an invalid KEYNAME.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 */
oe_result_t oe_get_private_key(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size);

/**
 * Dereference another enclave and reclaim its resources if this was the last
 * reference. Once this is performed, the other enclave can no longer be accessed.
 *
 * @param enclave The instance of the other enclave to be terminated, which was
 * previously obtained by calling a generated oe_create_<foo>_enclave() API.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_terminate_enclave(oe_enclave_t* enclave);

/**
 * An enclave can call this API to create a handle to pass to the host.
 *
 * @param[in] secure_address The address to create a handle for.
 * @param[out] handle A handle that can be passed to the host application.
 *
 * @returns Returns OE_OK on success.
 */
oe_result_t oe_allocate_handle(
    void* secure_address,
    ptrdiff_t* handle);

/**
 * An enclave can call this API to resolve a handle to the secure address.
 *
 * @param[in] handle The handle to resolve.
 * @param[out] secure_address The secure address associated with the handle.
 *
 * @returns Returns OE_OK on success.
 */
oe_result_t oe_resolve_handle(
    ptrdiff_t handle,
    void* secure_address);

/** 
 * An enclave can call this API to free a handle, e.g., before it frees the
 * memory the secure_address points to.
 *
 * @param[in] handle The handle to free.
 *
 * @returns Returns OE_OK on success.
 */
void oe_free_handle(ptrdiff_t handle);

/**
 * Generate a sequence of random bytes.
 *
 * This function generates a sequence of random bytes.
 *
 * @param data the buffer that will be filled with random bytes
 * @param size the size of the buffer
 *
 * @return OE_OK on success
 */
oe_result_t oe_random(void* data, size_t size);
```

##### 1.7.3.2 openenclave/bits/exception.h
This file defines data structures to set up vectored exception handlers in trusted application code.
```
/**
 * Divider exception code, used by vectored exception handler.
 */
#define OE_EXCEPTION_DIVIDE_BY_ZERO 0x0
/**
 * Debug exception code, used by vectored exception handler.
 */
#define OE_EXCEPTION_BREAKPOINT 0x1
/**
 * Bound range exceeded exception code, used by vectored exception handler.
 */
#define OE_EXCEPTION_BOUND_OUT_OF_RANGE 0x2
/**
 * Illegal instruction exception code, used by vectored exception handler.
 */
#define OE_EXCEPTION_ILLEGAL_INSTRUCTION 0x3
/**
 * Access violation exception code, used by vectored exception handler.
 */
#define OE_EXCEPTION_ACCESS_VIOLATION 0x4
/**
 * Page fault exception code, used by vectored exception handler.
 */
#define OE_EXCEPTION_PAGE_FAULT 0x5
/**
 * x87 floating point exception code, used by vectored exception handler.
 */
#define OE_EXCEPTION_X87_FLOAT_POINT 0x6
/**
 * Alignment check exception code, used by vectored exception handler.
 */
#define OE_EXCEPTION_MISALIGNMENT 0x7
/**
 * SIMD floating point exception code, used by vectored exception handler.
 */
#define OE_EXCEPTION_SIMD_FLOAT_POINT 0x8
/**
 * Unknown exception code, used by vectored exception handler.
 */
#define OE_EXCEPTION_UNKNOWN 0xFFFFFFFF

/**
 * Hardware exception flag, set when enclave software exited due to hardware
 * exception
 */
#define OE_EXCEPTION_FLAGS_HARDWARE 0x1
/**
 * Software exception flag, set when enclave software exited due to software
 * exception
 */
#define OE_EXCEPTION_FLAGS_SOFTWARE 0x2

/**
 * Blob that contains X87 and SSE data.
 */
typedef struct _oe_basic_xstate
{
    uint8_t blob[512]; /**< Holds XState i.e. X87 and SSE data */
} OE_ALIGNED(16) oe_basic_xstate_t;

/**
 * Register state to be saved before an exception and
 * restored after the exception has been handled in the enclave.
 */
typedef struct _oe_context
{
    /**
      * Exception flags.
      * OE_EXCEPTION_FLAGS_HARDWARE | OE_EXCEPTION_FLAGS_SOFTWARE
      */
    uint64_t flags;

    uint64_t rax; /**< Integer register rax */

    uint64_t rbx; /**< Integer register rbx */

    uint64_t rcx; /**< Integer register rcx */

    uint64_t rdx; /**< Integer register rdx */

    uint64_t rbp; /**< Integer register rbp */

    uint64_t rsp; /**< Integer register rsp */

    uint64_t rdi; /**< Integer register rdi */

    uint64_t rsi; /**< Integer register rsi */

    uint64_t r8; /**< Integer register r8 */

    uint64_t r9; /**< Integer register r9 */

    uint64_t r10; /**< Integer register r10 */

    uint64_t r11; /**< Integer register r11 */

    uint64_t r12; /**< Integer register r12 */

    uint64_t r13; /**< Integer register r13 */

    uint64_t r14; /**< Integer register r14 */

    uint64_t r15; /**< Integer register r15 */

    uint64_t rip; /**< Integer register rip */

    // Don't need to manipulate the segment registers directly.
    // Ignore them: CS, DS, ES, SS, GS, and FS.

    uint32_t mxcsr; /**< SSE control flags */

    oe_basic_xstate_t basic_xstate; /**< Basic XSTATE */

    // Don't need to manipulate other XSTATE (AVX etc.).
} oe_context_t;

/**
 * Exception context structure with the exception code, flags, address and
 * calling context of the exception.
 */
typedef struct _oe_exception_record
{
    uint32_t code; /**< Exception code */

    uint32_t flags; /**< Exception flags */

    uint64_t address; /**< Exception address */

    oe_context_t* context; /**< Exception context */
} oe_exception_record_t;

/**
 * oe_vectored_exception_handler_t - Function pointer for a vectored exception
 * handler in an enclave.
 * @param exception_context The record of exception information to be handled by
 * the function which includes any flags, the failure code, faulting address and
 * calling context for the exception.
 */
typedef uint64_t (*oe_vectored_exception_handler_t)(
    oe_exception_record_t* exception_context);
```

##### 1.7.3.3 openenclave/bits/properties.h
```
/**
 * This file defines the properties for an enclave.
 *
 * The enclave properties should only be defined once for all code compiled
 * into an enclave binary.
 * These properties can be overwritten at sign time by the oesign tool.
 */

/**
 * @cond DEV
 */
/* Injected by OE_SET_ENCLAVE_SGX macro and by the signing tool (oesign) */
#define OE_INFO_SECTION_NAME ".oeinfo"

/* Max number of threads in an enclave supported */
#define OE_SGX_MAX_TCS 32

typedef struct _oe_enclave_size_settings
{
    uint64_t num_heap_pages;
    uint64_t num_stack_pages;
    uint64_t num_tcs;
} oe_enclave_size_settings_t;

/* Base type for enclave properties */
typedef struct _oe_enclave_properties_header
{
    uint32_t size; /**< (0) Size of the extended structure */

    oe_enclave_type_t enclave_type; /**< (4) Enclave type */

    oe_enclave_size_settings_t size_settings; /**< (8) Enclave settings */
} oe_enclave_properties_header_t;

// oe_sgx_enclave_properties_t SGX enclave properties derived type
#define OE_SGX_FLAGS_DEBUG 0x0000000000000002ULL
#define OE_SGX_FLAGS_MODE64BIT 0x0000000000000004ULL
#define OE_SGX_SIGSTRUCT_SIZE 1808

typedef struct oe_sgx_enclave_config_t
{
    uint16_t product_id;
    uint16_t security_version;

    /* Padding to make packed and unpacked size the same */
    uint32_t padding;

    /* (OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT) */
    uint64_t attributes;
} oe_sgx_enclave_config_t;

/* Extends oe_enclave_properties_header_t base type */
typedef struct oe_sgx_enclave_properties_t
{
    /* (0) */
    oe_enclave_properties_header_t header;

    /* (32) */
    oe_sgx_enclave_config_t config;

    /* (48) */
    uint8_t sigstruct[OE_SGX_SIGSTRUCT_SIZE];
} oe_sgx_enclave_properties_t;

#define OE_INFO_SECTION_BEGIN __attribute__((section(".oeinfo")))
#define OE_INFO_SECTION_END

#define OE_MAKE_ATTRIBUTES(ALLOW_DEBUG) \
    (OE_SGX_FLAGS_MODE64BIT | (ALLOW_DEBUG ? OE_SGX_FLAGS_DEBUG : 0))

/**
 * @endcond
 */

// This macro initializes and injects an oe_sgx_enclave_properties_t struct
// into the .oeinfo section.

/**
 * Defines the SGX properties for an enclave.
 *
 * The enclave properties should only be defined once for all code compiled into
 * an enclave binary. These properties can be overwritten at sign time by
 * the oesign tool.
 *
 * @param PRODUCT_ID ISV assigned Product ID (ISVPRODID) to use in the
 * enclave signature
 * @param SECURITY_VERSION ISV assigned Security Version number (ISVSVN)
 * to use in the enclave signature
 * @param ALLOW_DEBUG If true, allows the enclave to be created with
 * OE_ENCLAVE_FLAG_DEBUG and debugged at runtime
 * @param HEAP_PAGE_COUNT Number of heap pages to allocate in the enclave
 * @param STACK_PAGE_COUNT Number of stack pages per thread to reserve in
 * the enclave
 * @param TCS_COUNT Number of concurrent threads in an enclave to support
 */
// Note: disable clang-format since it badly misformats this macro
// clang-format off

#define OE_SET_ENCLAVE_SGX(                                               \
    PRODUCT_ID,                                                           \
    SECURITY_VERSION,                                                     \
    ALLOW_DEBUG,                                                          \
    HEAP_PAGE_COUNT,                                                      \
    STACK_PAGE_COUNT,                                                     \
    TCS_COUNT)                                                            \
    OE_INFO_SECTION_BEGIN                                                 \
    OE_EXPORT_CONST oe_sgx_enclave_properties_t oe_enclave_properties_sgx = \
    {                                                                     \
        .header =                                                         \
        {                                                                 \
            .size = sizeof(oe_sgx_enclave_properties_t),                  \
            .enclave_type = OE_ENCLAVE_TYPE_SGX,                          \
            .size_settings =                                              \
            {                                                             \
                .num_heap_pages = HEAP_PAGE_COUNT,                        \
                .num_stack_pages = STACK_PAGE_COUNT,                      \
                .num_tcs = TCS_COUNT                                      \
            }                                                             \
        },                                                                \
        .config =                                                         \
        {                                                                 \
            .product_id = PRODUCT_ID,                                     \
            .security_version = SECURITY_VERSION,                         \
            .padding = 0,                                                 \
            .attributes = OE_MAKE_ATTRIBUTES(ALLOW_DEBUG)                 \
        },                                                                \
        .sigstruct =                                                      \
        {                                                                 \
            0                                                             \
        }                                                                 \
    };                                                                    \
    OE_INFO_SECTION_END

// clang-format on

/**
 * This function sets the minimum value of issue dates of CRL and TCB info
 * accepted by the enclave. CRL and TCB info issued before this date
 * are rejected for attestation.
 * This function is not thread safe.
 * Results of calling this function multiple times from within an enclave
 * are undefined.
 */
oe_result_t __oe_sgx_set_minimum_crl_tcb_issue_date(
    uint32_t year,
    uint32_t month,
    uint32_t day,
    uint32_t hours,
    uint32_t minutes,
    uint32_t seconds);
```
