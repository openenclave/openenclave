#ifndef _ENCIDL_TESTER_T_H
#define _ENCIDL_TESTER_T_H

#include <openenclave.h>

/*
********************************************************************************
**
** Structure definitions
**
********************************************************************************
*/

struct Date
{
    oe_uint32_t mm;
    oe_uint32_t dd;
    oe_uint32_t yyyy;
};

extern const OE_StructTI Date_ti;

struct Object
{
    oe_size_t id;
    char *name;
};

extern const OE_StructTI Object_ti;

struct Node
{
    oe_uint32_t value;
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

OE_EXTERNC oe_uint32_t ReturnUint32();

OE_EXTERNC char *ReturnStr();

OE_EXTERNC struct Date ReturnDate();

OE_EXTERNC struct Object ReturnObject();

OE_EXTERNC struct Object *ReturnObjects(
    oe_size_t count);

OE_EXTERNC struct Node *ReturnLinkedList();

OE_EXTERNC char *TestStrdup(
    const char *s);

OE_EXTERNC oe_int32_t CopyObject(
    struct Object *dest,
    const struct Object *src);

OE_EXTERNC oe_int32_t CopyObjects(
    struct Object dest[2],
    const struct Object src[2]);

OE_EXTERNC oe_int32_t ECALL_MultipleParams(
    const char *strIn,
    oe_uint32_t numIn,
    const struct Object *objectIn,
    char *strOut,
    oe_uint32_t *numOut,
    struct Object *objectOut,
    struct Object **objectRefOut);

OE_EXTERNC oe_int32_t GetObjectRef(
    struct Object **object);

OE_EXTERNC oe_int32_t ModifyObject(
    struct Object *object);

OE_EXTERNC oe_size_t TestStrlcpy(
    char *dest,
    const char *src,
    oe_size_t dsize);

OE_EXTERNC oe_size_t TestOptQualifier(
    char *p1,
    const char *p2,
    oe_size_t p1size);

OE_EXTERNC int *ReturnIntPtr(
    int *p,
    oe_size_t n);

OE_EXTERNC void TestCallback(
    void *func);

OE_EXTERNC oe_bool TestIntPtrRef(
    int **intPtrOut,
    oe_size_t n);

OE_EXTERNC void TestBufferOverun(
    char src[8]);

OE_EXTERNC void *ReturnEnclaveMemory();

OE_EXTERNC void TestBufferCopy(
    void *dest,
    const void *src,
    oe_size_t n,
    oe_bool forceOverwrite);

/*
********************************************************************************
**
** Outbound calls
**
********************************************************************************
*/

OE_EXTERNC OE_Result OCALL_MultipleParams(
    oe_int32_t *ret,
    const char *strIn,
    oe_uint32_t numIn,
    const struct Object *objectIn,
    char *strOut,
    oe_uint32_t *numOut,
    struct Object *objectOut,
    struct Object **objectRefOut);

#endif /* _ENCIDL_TESTER_T_H */
