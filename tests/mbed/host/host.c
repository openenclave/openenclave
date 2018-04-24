// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include "args.h"
#include "ocalls.h"

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

char *data_file_name;

typedef struct FILE_Args
{
    FILE*     F_ptr;
    char*     path;
    char*     mode;
    char*     buf;
    void      *ptr;
    int       ret;
    
    long int  li_var;
    int       i_var;
    int       len;

} F_Args;

typedef struct _Args
{
    char* test;
    int ret;
} Args;


#define DEBUG
#undef  DEBUG

OE_OCALL void OE_FOpen( void * F_ARGS )
{
    FILE *fp;
    F_Args* args = (F_Args*)F_ARGS;
#ifdef DEBUG
    printf("#### %s ###########\n", args->path);     
#endif
    fp = fopen(args->path, args->mode );
    if ( fp  == NULL)
       printf("fopen error");
    else {
#ifdef DEBUG
         printf("\n ^^^^^^^file opened address fp =%p &&&&&&&&&\n",fp);
#endif
         args->F_ptr = fp ;
    }
    return;
}

OE_OCALL void OE_FClose( void * F_ARGS )
{
    int ret;
    F_Args* args = (F_Args*)F_ARGS;

    ret = fclose( args->F_ptr );

#ifdef DEBUG
    printf("\n fclose Ret = %d \n",ret);
#endif
    args->ret = ret;
    return ;
}

OE_OCALL void OE_FEof( void * F_ARGS )
{
    int ret;
    F_Args* args = (F_Args*)F_ARGS;

    ret = feof( args->F_ptr );

#ifdef DEBUG
    printf("\n feof Ret = %d \n",ret);
#endif
    args->ret = ret;
    return ;
}
 
OE_OCALL void OE_FError( void * F_ARGS )
{
    int ret;
    F_Args* args = (F_Args*)F_ARGS;

    ret = ferror( args->F_ptr );

#ifdef DEBUG
    printf("\n feof Ret = %d \n",ret);
#endif
    args->ret = ret;
    return ;
}
 
OE_OCALL void OE_FGets( void * F_ARGS )
{
    char* ret;
    F_Args* args = (F_Args*)F_ARGS;

    ret = fgets( args->buf, args->len, args->F_ptr);

#ifdef DEBUG
    printf("\n fgets Ret = %d --- buf: %s \n",ret ,args->buf);
#endif
    args->ptr = (void*)ret;
    return ;
}

OE_OCALL void OE_FRead( void * F_ARGS )
{
    int ret;
    F_Args* args = (F_Args*)F_ARGS;

    ret = fread( args->buf, args->len, (size_t)args->i_var, args->F_ptr);

#ifdef DEBUG
    printf("\n fgets Ret = %d --- buf: %s \n",ret ,args->buf);
#endif
    args->ret = ret;
    return ;
}

OE_OCALL void OE_FWrite( void * F_ARGS )
{
    int ret;
    F_Args* args = (F_Args*)F_ARGS;

    ret = fwrite( args->buf, args->len, (size_t)args->i_var, args->F_ptr);

#ifdef DEBUG
    printf("\n fwrite Ret = %d --- buf: %s \n",ret ,args->buf);
#endif
    args->ret = ret;
    return ;
}


OE_OCALL void OE_FSeek( void * F_ARGS )
{
    int ret;
    F_Args* args = (F_Args*)F_ARGS;

    ret = fseek( args->F_ptr, args->li_var, args->i_var);

#ifdef DEBUG
    printf("\n fgets Ret = %d \n",ret );
#endif
    args->ret = ret;
    return ;
}

OE_OCALL void OE_FPutc( void * F_ARGS )
{
    int ret;
    F_Args* args = (F_Args*)F_ARGS;

    ret = fputc( args->i_var, args->F_ptr);

#ifdef DEBUG
    printf("\n fputc Ret = %d \n",ret );
#endif
    args->ret = ret;
    return ;
}

 
OE_OCALL void OE_FTell( void * F_ARGS )
{
    int ret;
    F_Args* args = (F_Args*)F_ARGS;

    ret = ftell( args->F_ptr);

#ifdef DEBUG
    printf("\n fgets Ret = %d --- \n",ret);
#endif
    args->ret = ret;
    return ;
}

OE_OCALL void OE_OPen_dir( void * F_ARGS )
{
    F_Args* args = (F_Args*)F_ARGS;

    args->ptr = (void *)opendir(args->path);

#ifdef DEBUG
    printf("\n opendir Ret = %d --- buf: %s \n",ret ,args->buf);
#endif
    return ;
}

OE_OCALL void OE_CLose_dir( void * F_ARGS )
{
    F_Args* args = (F_Args*)F_ARGS;

    args->ret = closedir((DIR *)args->ptr);

#ifdef DEBUG
    printf("\n close dir Ret = %d --- buf: %s \n",ret ,args->buf);
#endif
    return ;
}

OE_OCALL void OE_REad_dir( void * F_ARGS )
{
    F_Args* args = (F_Args*)F_ARGS;

    args->ptr = (void* )readdir((DIR *)args->ptr);

#ifdef DEBUG
    printf("\n close dir Ret = %d --- buf: %s \n",ret ,args->buf);
#endif
    return ;
}

OE_OCALL void OE_STat( void * F_ARGS )
{
    F_Args* args = (F_Args*)F_ARGS;

    args->ret = (int)stat( args->path, (struct stat *)args->ptr);

#ifdef DEBUG
    printf("\n stat  Ret = %d --- buf: %s \n",args->ret );
#endif
    return ;
}

void * find_data_file(char *str)
{       char *token,*temp; 
        char dil[20] = ".signed.so";
        char tail[20] = ".data" ;
        char checker[20] = "test_suite_";
        token = strstr(str,checker);
       if (token == NULL){
       printf("!!File is not in format !!!!\n");
        return token;
       }
        printf( "###after st1 out %s\n",token);
        temp = strstr((token),dil);
       if(temp == NULL){
       return temp;
}
        printf( "###after dil out %s\n", token);
        strcpy(temp,tail);
        printf( "###final out in find_data_file  %s\n", token);
return token;
}

void Test(OE_Enclave* enclave)
{

    char cwd[1024];
    char tail[1024] = "3rdparty/mbedtls/mbedtls/tests/suites/";
    char out[1024]  = {NULL};
    char s[2] = "/";
    char *token;

    Args args;
    args.ret = 1;
    args.test = NULL;

    if (getcwd(cwd, sizeof(cwd)) != NULL)
            fprintf(stdout, "Current working dir: %s\n", cwd);
    else
            perror("getcwd() error");
    token = strtok(cwd, s);
    /* walk through other tokens */
    out[0] = '/' ;
    while( ((token != NULL) && (strcmp(token,"build"))) ) {
            strcat(out,token);
            strcat(out,"/");
            token = strtok(NULL, s);
    }
    strcat(out,tail);
    printf( "###final out in Test %s\n", out );
    args.test = out;
    strcat(args.test,data_file_name);
    printf("###final args.test contains data file path  in Test %s\n", args.test);

    OE_Result result = OE_CallEnclave(enclave, "Test", &args);
    assert(result == OE_OK);

    if (args.ret == 0)
    {
        printf("PASSED: %s\n", args.test);
    }
    else
    {
        printf("FAILED: %s (ret=%d)\n", args.test, args.ret);
        abort();
    }
}

static void _ExitOCall(uint64_t argIn, uint64_t* argOut)
{
    exit(argIn);
}

int main(int argc, const char* argv[])
{
    OE_Result result;
    char temp[500];
    OE_Enclave* enclave = NULL;
    uint32_t flags = OE_GetCreateFlags();

    // Check argument count:
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf("=== %s: %s\n", argv[0], argv[1]);
    
    strcpy(temp,argv[1]);
    data_file_name =(char *) find_data_file(temp);
    if (data_file_name == NULL){
       printf("!!!!! it is not sighned.so file !!!! \n");
       return 0;
    }

    printf( "###after find_data_file call data_file_name is : %s\n", data_file_name);


    // Create the enclave:
    if ((result = OE_CreateEnclave(argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        OE_PutErr("OE_CreateEnclave(): result=%u", result);

    // Register to handle OCALL_EXIT from tests.
    OE_RegisterOCall(OCALL_EXIT, _ExitOCall);

    // Invoke "Test()" in the enclave.
    Test(enclave);

    // Shutdown the enclave.
    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);

    printf("\n");

    return 0;
}
