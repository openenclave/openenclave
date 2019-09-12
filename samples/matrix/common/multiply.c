// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>

#include "multiply.h"

#define NUM 256
typedef double TYPE;
typedef TYPE array[NUM];
typedef unsigned long long UINT64;

// routine to initialize an array with data
void init_arr(TYPE row, TYPE col, TYPE off, TYPE a[][NUM])
{
    int i, j;

    for (i = 0; i < NUM; i++)
    {
        for (j = 0; j < NUM; j++)
        {
            a[i][j] = row * i + col * j + off;
        }
    }
}

// routine to print out contents of small arrays
void print_arr(char* name, TYPE array[][NUM])
{
    int i, j;

    printf("\n%s\n", name);
    for (i = 0; i < NUM; i++)
    {
        for (j = 0; j < NUM; j++)
        {
            printf("%g\t", array[i][j]);
        }
        printf("\n");
        fflush(stdout);
    }
}

// routine to do matrix multiplication
void multiply(
    int msize,
    TYPE a[][NUM],
    TYPE b[][NUM],
    TYPE c[][NUM],
    TYPE t[][NUM])
{
    int i, j, k;

    // Basic serial implementation
    for (i = 0; i < msize; i++)
    {
        for (j = 0; j < msize; j++)
        {
            for (k = 0; k < msize; k++)
            {
                c[i][j] = c[i][j] + a[i][k] * b[k][j];
            }
        }
    }
}

void task()
{
    char *buf1, *buf2, *buf3, *buf4;
    char *addr1, *addr2, *addr3, *addr4;
    array *a, *b, *c, *t;
    int Offset_Addr1 = 128, Offset_Addr2 = 192, Offset_Addr3 = 0,
        Offset_Addr4 = 64;

    buf1 = (char*)malloc(NUM * NUM * (sizeof(double)) + 1024);
    printf("Addr of buf1 = %p\n", buf1);
    fflush(stdout);
    addr1 = buf1 + 256 - ((UINT64)buf1 % 256) + (UINT64)Offset_Addr1;
    printf("Offs of buf1 = %p\n", addr1);
    fflush(stdout);

    buf2 = (char*)malloc(NUM * NUM * (sizeof(double)) + 1024);
    printf("Addr of buf2 = %p\n", buf2);
    fflush(stdout);
    addr2 = buf2 + 256 - ((UINT64)buf2 % 256) + (UINT64)Offset_Addr2;
    printf("Offs of buf2 = %p\n", addr2);
    fflush(stdout);

    buf3 = (char*)malloc(NUM * NUM * (sizeof(double)) + 1024);
    printf("Addr of buf3 = %p\n", buf3);
    fflush(stdout);
    addr3 = buf3 + 256 - ((UINT64)buf3 % 256) + (UINT64)Offset_Addr3;
    printf("Offs of buf3 = %p\n", addr3);
    fflush(stdout);

    buf4 = (char*)malloc(NUM * NUM * (sizeof(double)) + 1024);
    printf("Addr of buf4 = %p\n", buf4);
    fflush(stdout);
    addr4 = buf4 + 256 - ((UINT64)buf4 % 256) + (UINT64)Offset_Addr4;
    printf("Offs of buf4 = %p\n", addr4);
    fflush(stdout);

    a = (array*)addr1;
    b = (array*)addr2;
    c = (array*)addr3;
    t = (array*)addr4;

    // initialize the arrays with data
    init_arr(3, -2, 1, a);
    init_arr(-2, 1, 3, b);

    // do multiplication
    for (int i = 0; i < 50; i++)
        multiply(NUM, a, b, c, t);

    // print simple test case of data to be sure multiplication is correct
    if (NUM < 5)
    {
        print_arr("a", a);
        fflush(stdout);
        print_arr("b", b);
        fflush(stdout);
        print_arr("c", c);
        fflush(stdout);
    }

    // free memory
    free(buf1);
    free(buf2);
    free(buf3);
    free(buf4);
}
