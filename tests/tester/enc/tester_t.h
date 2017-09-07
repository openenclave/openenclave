#ifndef _ENCIDL_TESTER_T_H
#define _ENCIDL_TESTER_T_H

#include <openenclave/enclave.h>

/*
********************************************************************************
**
** Structure definitions
**
********************************************************************************
*/

struct Date
{
    uint32_t mm;
    uint32_t dd;
    uint32_t yyyy;
};

extern const OE_StructTI Date_ti;

struct Object
{
    size_t id;
    char *name;
};

extern const OE_StructTI Object_ti;

struct Node
{
    uint32_t value;
    struct Node *next;
};

extern const OE_StructTI Node_ti;

/*
********************************************************************************
**
** Inbound calls
**
********************************************************************************
*/

OE_EXTERNC void ReturnVoid();

OE_EXTERNC uint32_t ReturnUint32();

OE_EXTERNC char *ReturnStr();

OE_EXTERNC struct Date ReturnDate();

OE_EXTERNC struct Object ReturnObject();

OE_EXTERNC struct Object *ReturnObjects(
    size_t count);

OE_EXTERNC struct Node *ReturnLinkedList();

OE_EXTERNC char *TestStrdup(
    const char *s);

OE_EXTERNC int32_t CopyObject(
    struct Object *dest,
    const struct Object *src);

OE_EXTERNC int32_t CopyObjects(
    struct Object dest[2],
    const struct Object src[2]);

OE_EXTERNC int32_t ECALL_MultipleParams(
    const char *strIn,
    uint32_t numIn,
    const struct Object *objectIn,
    char *strOut,
    uint32_t *numOut,
    struct Object *objectOut,
    struct Object **objectRefOut);

OE_EXTERNC int32_t GetObjectRef(
    struct Object **object);

OE_EXTERNC int32_t ModifyObject(
    struct Object *object);

OE_EXTERNC size_t TestStrlcpy(
    char *dest,
    const char *src,
    size_t dsize);

OE_EXTERNC size_t TestOptQualifier(
    char *p1,
    const char *p2,
    size_t p1size);

OE_EXTERNC int *ReturnIntPtr(
    int *p,
    size_t n);

OE_EXTERNC void TestCallback(
    void *func);

OE_EXTERNC bool TestIntPtrRef(
    int **intPtrOut,
    size_t n);

OE_EXTERNC void TestBufferOverun(
    char src[8]);

OE_EXTERNC void *ReturnEnclaveMemory();

OE_EXTERNC void TestBufferCopy(
    void *dest,
    const void *src,
    size_t n,
    bool forceOverwrite);

/*
********************************************************************************
**
** Outbound calls
**
********************************************************************************
*/

OE_EXTERNC OE_Result OCALL_MultipleParams(
    int32_t *ret,
    const char *strIn,
    uint32_t numIn,
    const struct Object *objectIn,
    char *strOut,
    uint32_t *numOut,
    struct Object *objectOut,
    struct Object **objectRefOut);

#endif /* _ENCIDL_TESTER_T_H */
