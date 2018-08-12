#ifndef USER_DATA_H
#define USER_DATA_H

typedef struct _MyStruct
{
    int value[10];
} MyStruct;

typedef struct MyStruct* pMyStruct;

typedef int(MyArray)[10];

struct ZMyStruct
{
};

typedef struct ZMyStruct* pZMyStruct;

typedef enum { Enum_A, Enum_B } MyEnum;

typedef int* pMyBuf;

typedef float* pZMyBuf;

#endif // USER_DATA_H
