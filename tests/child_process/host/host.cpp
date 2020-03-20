// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <unistd.h>
#include <sys/wait.h>

#include "child_process_u.h"

bool MULTI_THREAD_FLAG = true;

void ocall_stay(void)
{
    //sleep for 5 seconds.
    sleep(5);
}

int main(int argc, const char* argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH TEST_NUMBER\n", argv[0]);
        exit(1);
    }
    oe_enclave_t* enclave = NULL;
    const uint32_t flags = oe_get_create_flags();
    int fpipe[2];
    pipe(fpipe);
    int pid;
    oe_result_t result =
        oe_create_child_process_enclave(argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    oe_result_t result2;
    OE_TEST(result == OE_OK);

    pid = fork();
    switch (atoi(argv[2]))
    {
        case 1:
            if (pid == 0)    //child process
            {
                close(fpipe[0]);
                fprintf(stdout, "child pid = %d\n", getpid());
                unsigned int magic = 2;
                result2 =  EnclaveGetMagic(enclave,&magic);
                OE_TEST(result2 != OE_OK);
                OE_TEST(magic == 2);        
                write(fpipe[1],&result2,sizeof(oe_result_t));
                close(fpipe[1]);
                _exit(EXIT_SUCCESS);
            }
            else if(pid >0)   //parent process
            {
                fprintf(stdout, "parenet pid = %d\n", getpid());
                close(fpipe[1]);
                read(fpipe[0],&result,sizeof(oe_result_t));
                close(fpipe[0]);
                OE_TEST(result == OE_OK);
                oe_terminate_enclave(enclave);
                wait(NULL);    
            }
            else
            {
                fprintf(stderr, "failed to create child process.\n");        
            }
             break;
        case 2:
            if (pid == 0)    //child process
            {
   
                result =  oe_terminate_enclave(enclave);
            OE_TEST(result != OE_OK);
   
            }
             else if(pid >0)   //parent process
            {
                unsigned int magic;

            result2 =  EnclaveGetMagic(enclave,&magic);
                OE_TEST(result2 == OE_OK);
                OE_TEST(0x1234 == magic);
                oe_terminate_enclave(enclave);
                wait(NULL);    
            }
            else
           {
               fprintf(stderr, "failed to create child process.\n");
           }
            break;
	default:
            break;
    }      
    // Clean up the enclave
    if (enclave)
        oe_terminate_enclave(enclave);

    return 0;
}
