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
This sample shows how trusted application code is loaded, and how normal application code and trusted application code can communicate using an RPC-like API the app developer defines in an EDL file.

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
In this scenario, an application wants to get a report that can attest to the integrity of a trusted application, and verify a report that it received from another trusted application (e.g., across a TLS connection).  This can be triggered from either normal application code or trusted application code, with similar APIs, but in either case, the operation is actually performed and signatures generated or checked within the Trusted Execution Environment (i.e., by the library linked into the trusted applicat
ion code).

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

oe_result_t SendOwnReport(oe_enclave_t* enclave)
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

    // … make sure there's no other uses of the widget pointer. If the trusted
    // application is multithreaded, this also means that thread synchronization
    // must be handled and only continue once no references remain …

    // Clean up widget state.
    free(widget);
}
```

### 1.7	Interface Definition

#### 1.7.1 Standard APIs
The following APIs are exposed to normal applications as well as trusted application code.

##### 1.7.1.1 Standard C file APIs
The following file APIs that operate on already-opened files are exposed to trusted applications as well:

* fflush, ferror, fclose, feof, fread, fseek, ftell, fwrite, fputs, fgets

These are #define’ed to oe_* equivalents by default, which have the same syntax as the POSIX equivalents:

* oe_fopen, oe_fflush, oe_ferror, oe_fclose, oe_feof, oe_fread, oe_fseek, oe_ftell, oe_fwrite, oe_fputs, oe_fgets

The following file APIs are exposed to trusted applications as well:

* fopen, remove

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
The following POSIX file enumeration APIs are exposed to trusted applications as well:
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

These are #define’ed to oe_* equivalents by default, which have the same syntax as the POSIX equivalents:

* oe_accept, oe_bind, oe_connect, oe_fd_isset, oe_freeaddrinfo, oe_getpeername, oe_getsockname, oe_getsockopt, oe_listen, oe_recv, oe_select, oe_send, oe_setsockopt, oe_shutdown 

The following POSIX socket APIs are exposed to trusted applications as well:

* socket, getaddrinfo, gethostname, getnameinfo

These are #defined to oe_* equivalents by default, which have the same syntax as the POSIX equivalents, except they have an additional security mode argument (the former list all have sockets as input arguments, unlike the ones below):

* oe_socket, oe_getaddrinfo, oe_gethostname, oe_getnameinfo

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

These are #define’ed to oe_* equivalents by default, which have the same syntax as the Winsock equivalents except for an additional oe_network_security_t argument:

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

##### 1.7.2 Additional Open Enclave APIs

Other APIs are covered in more detail in the automatically generated
[API docs](https://ms-iot.github.io/openenclave/api/files.html).
