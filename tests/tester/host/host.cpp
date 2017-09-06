#include <openenclave/host.h>
#include <openenclave/bits/tests.h>
#include <climits>
#include <cwchar>
#include <cstdarg>
#include <cassert>
#include "tester_u.h"

const char* arg0;

int ConstructObject(Object& o, size_t id, const char* name)
{
    memset(&o, 0, sizeof(o));

    o.id = id;

    if (name)
    {
        if (!(o.name = strdup(name)))
            return -1;
    }

    return 0;
}

OE_EXTERNC int32_t OCALL_MultipleParams(
    const char *strIn,
    uint32_t numIn,
    const struct Object *objectIn,
    char *strOut,
    uint32_t *numOut,
    struct Object *objectOut,
    struct Object **objectRefOut)
{
    return -1;
}

void __CheckResult(
    const char* file,
    unsigned int line,
    OE_Result result, 
    const char* msg)
{
    if (result != OE_OK)
    {
       fprintf(stderr, "%s(%u): result=%u: %s: %s\n", file, line , result, 
            OE_ResultStr(result), msg);
        exit(1);
    }
}

#define CheckResult(...) __CheckResult(__FILE__, __LINE__, __VA_ARGS__)

bool CheckObject(
    const Object& x,
    size_t id,
    const char* name)
{
    return x.id == id && strcmp(x.name, name) == 0;
}

extern "C" void Callback(const char* str)
{
    printf("Callback(str=%s)\n", str);
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    result = OE_CreateEnclave(argv[1], 0, &enclave);
    if (result != OE_OK)
        OE_PutErr("cannot create enclave");

    // Test: ReturnVoid()
    {
        result = ReturnVoid(enclave);
        CheckResult(result, "ReturnVoid()");
        printf("=== passed ReturnVoid()\n");
    }

    // Test: ReturnUint32()
    {
        uint32_t ret = 0;
        result = ReturnUint32(enclave, &ret);
        CheckResult(result, "ReturnUint32()");
        OE_TEST(ret == 32);
        printf("=== passed ReturnUint32()\n");
    }

    // Test: ReturnStr()
    {
        char* str = 0;
        result = ReturnStr(enclave, &str);
        CheckResult(result, "ReturnStr()");
        OE_TEST(str != NULL);
        OE_TEST(strcmp(str, "str") == 0);
        free(str);
        printf("=== passed ReturnStr()\n");
    }

    // Test: ReturnDate()
    {
        Date d;
        memset(&d, 0, sizeof(d));
        result = ReturnDate(enclave, &d);
        CheckResult(result, "ReturnDate()");
        OE_TEST(d.mm == 12 && d.dd == 30 && d.yyyy == 2017);
        printf("=== passed ReturnDate()\n");
    }

    // Test: ReturnObject()
    {
        Object o;
        memset(&o, 0, sizeof(o));
        result = ReturnObject(enclave, &o);
        CheckResult(result, "ReturnObject()");
        OE_TEST(o.name);
        OE_TEST(strcmp(o.name, "Object") == 0);
        OE_TEST(o.id == 6);
        OE_DestroyStruct(&Object_ti, &o, free);
        printf("=== passed ReturnObject()\n");
    }

    // Test: ReturnLinkedList()
    {
        Node* p = NULL;
        result = ReturnLinkedList(enclave, &p);
        CheckResult(result, "ReturnLinkedList()");
        OE_TEST(p);
        OE_TEST(p->value == 1);
        OE_TEST(p->next);
        OE_TEST(p->next->value == 2);
        OE_TEST(p->next->next);
        OE_TEST(p->next->next->value == 3);
        free(p->next->next);
        free(p->next);
        free(p);
        printf("=== passed ReturnLinkedList()\n");
    }

    // Test: ReturnObjects()
    {
        Object* p = NULL;
        result = ReturnObjects(enclave, &p, 3);
        CheckResult(result, "ReturnObjects()");
        OE_TEST(p);
        OE_TEST(p[0].id == 0);
        OE_TEST(strcmp(p[0].name, "Object0") == 0);
        OE_TEST(p[1].id == 1);
        OE_TEST(strcmp(p[1].name, "Object1") == 0);
        OE_TEST(p[2].id == 2);
        OE_TEST(strcmp(p[2].name, "Object2") == 0);
        OE_DestroyStruct(&Object_ti, &p[0], free);
        OE_DestroyStruct(&Object_ti, &p[1], free);
        OE_DestroyStruct(&Object_ti, &p[2], free);
        free(p);
        printf("=== passed ReturnObjects()\n");
    }

    // Test: TestStrdup()
    {
        char* s = NULL;
        result = TestStrdup(enclave, &s, "TestStrdup");
        CheckResult(result, "CheckResult()");
        OE_TEST(s);
        OE_TEST(strcmp(s, "TestStrdup") == 0);
        free(s);
        printf("=== passed TestStrdup()\n");
    }

    // Test: CopyObject()
    {
        Object src;
        ConstructObject(src, 274, "My Object");
        Object dest;
        ConstructObject(dest, 0, "xxxxxx");
        int32_t ret = -1;
        result = CopyObject(enclave, &ret, &dest, &src);
        CheckResult(result, "CopyObject()");
        OE_TEST(ret == 0);
        OE_TEST(CheckObject(src, 274, "My Object"));
        OE_TEST(CheckObject(dest, 274, "My Object"));
        OE_DestroyStruct(&Object_ti, &src, free);
        OE_DestroyStruct(&Object_ti, &dest, free);
        printf("=== passed CopyObject()\n");
    }

    // Test: CopyObject()
    {
        Object src[2];
        Object dest[2];
        ConstructObject(src[0], 0, "O0");
        ConstructObject(src[1], 1, "O1");
        ConstructObject(dest[0], 0, NULL);
        ConstructObject(dest[1], 0, NULL);

        int32_t ret = -1;
        result = CopyObjects(enclave, &ret, dest, src);
        CheckResult(result, "CopyObjects()");
        OE_TEST(ret == 0);
        OE_TEST(CheckObject(dest[0], 0, "O0"));
        OE_TEST(CheckObject(dest[1], 1, "O1"));
        OE_DestroyStruct(&Object_ti, &src[0], free);
        OE_DestroyStruct(&Object_ti, &src[1], free);
        OE_DestroyStruct(&Object_ti, &dest[0], free);
        OE_DestroyStruct(&Object_ti, &dest[1], free);
        printf("=== passed CopyObjects()\n");
    }

    // Test: ECALL_MultipleParams()
    {
        Object objectIn;
        ConstructObject(objectIn, 111, "0111");
        Object objectOut;
        memset(&objectOut, 0, sizeof(Object));
        int32_t ret = -1;
        char strOut[128] = { '\0' };
        uint32_t numOut = 0xFFFFFFFF;
        Object* objectRefOut = NULL;
        result = ECALL_MultipleParams(
            enclave, 
            &ret, 
            "strIn",
            999,
            &objectIn,
            strOut,
            &numOut,
            &objectOut,
            &objectRefOut);
        CheckResult(result, "ECALL_MultipleParams()");
        OE_TEST(ret == 0);
        OE_TEST(strcmp(strOut, "strIn") == 0);
        OE_TEST(numOut == 999);
        OE_TEST(CheckObject(objectOut, 111, "0111"));
        OE_DestroyStruct(&Object_ti, &objectIn, free);
        OE_DestroyStruct(&Object_ti, &objectOut, free);
        OE_FreeStruct(&Object_ti, objectRefOut, free);
        printf("=== passed ECALL_MultipleParams()\n");
    }

    // Test: GetObjectRef()
    {
        struct Object* object = NULL;
        int32_t ret = -1;
        result = GetObjectRef(enclave, &ret, &object);
        CheckResult(result, "GetObjectRef()");
        OE_TEST(ret == 0);
        OE_TEST(object);
        OE_TEST(CheckObject(*object, 12, "GetObjectRef"));
        OE_FreeStruct(&Object_ti, object, free);
        printf("=== passed GetObjectRef()\n");
    }

    // Test: GetObjectRef2()
    {
        int32_t ret = -1;
        result = GetObjectRef(enclave, &ret, NULL);
        CheckResult(result, "GetObjectRef2()");
        OE_TEST(ret == -1);
        printf("=== passed GetObjectRef2()\n");
    }

    // Test: ModifyObject()
    {
        struct Object* object = 
            (struct Object*)calloc(1, sizeof(struct Object));
        object->id = 1;
        object->name = strdup("Obj1");

        int32_t ret = -1;
        result = ModifyObject(enclave, &ret, object);
        CheckResult(result, "ModifyObject()");
        OE_TEST(ret == 0);
        OE_FreeStruct(&Object_ti, object, free);
        printf("=== passed ModifyObject()\n");
    }

    // Test Strlcpy():
    {
        char buf[20];
        size_t res;
        const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
        result = TestStrlcpy(enclave, &res, buf, alphabet, sizeof(buf));
        CheckResult(result, "TestStrlcpy()");
        OE_TEST(res == 26);
        OE_TEST(buf[19] == '\0');
        OE_TEST(strlen(buf) == 19);
        OE_TEST(strncmp(buf, alphabet, sizeof(buf)-1) == 0);
        printf("=== passed TestStlcpy(): 1\n");
    }

    // TestStrlcpy():
    {
        char buf[20];
        size_t res;
        const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
        result = TestStrlcpy(enclave, &res, NULL, alphabet, sizeof(buf));
        CheckResult(result, "TestStlcpy()");
        printf("=== passed TestStlcpy(): 2\n");
    }

    // TestStrlcpy():
    {
        char buf[20];
        size_t res;
        result = TestStrlcpy(enclave, &res, buf, NULL, sizeof(buf));
        CheckResult(result, "TestStlcpy()");
        printf("=== passed TestStlcpy(): 3\n");
    }

    // TestStrlcpy():
    {
        char buf[20];
        size_t res;
        result = TestStrlcpy(enclave, &res, buf, NULL, sizeof(buf));
        CheckResult(result, "TestStlcpy()");
        printf("=== passed TestStlcpy(): 4\n");
    }

    // TestOptQualifier():
    {
        size_t ret;
        result = TestOptQualifier(enclave, &ret, NULL, NULL, 12345);
        CheckResult(result, "TestOptQualifier()");
        OE_TEST(ret == 0);
        printf("=== passed TestOptQualifier()\n");
    }

    // ReturnIntPtr():
    {
        int* ret;
        int arr[3] = { 1000, 2000, 3000 };
        result = ReturnIntPtr(enclave, &ret, arr, OE_COUNTOF(arr));
        CheckResult(result, "ReturnIntPtr()");
        OE_TEST(ret != NULL);
        OE_TEST(memcmp(ret, arr, OE_COUNTOF(arr)) == 0);
        free(ret);
        printf("=== passed ReturnIntPtr(): 1\n");
    }

    // ReturnIntPtr():
    {
        int* ret;
        result = ReturnIntPtr(enclave, &ret, NULL, 0);
        CheckResult(result, "ReturnIntPtr()");
        OE_TEST(ret == NULL);
        printf("=== passed ReturnIntPtr(): 2\n");
    }

    // TestIntPtrRef()
    {
        int* p = NULL;
        bool flag;
        size_t n = 1000;
        result = TestIntPtrRef(enclave, &flag, &p, n);
        CheckResult(result, "TestIntPtrRef()");
        OE_TEST(flag);
        OE_TEST(p != NULL);

        for (size_t i = 0; i < n; i++)
            OE_TEST(p[i] == (int)i);

        free(p);
        printf("=== passed TestIntPtrRef(): 2\n");
    }

    // TestBufferOverun()
    {
        char buf[8];
        result = TestBufferOverun(enclave, buf);
        OE_TEST(result == OE_OK);
        printf("=== passed TestBufferOverun(): 2\n");
    }

    // ReturnEnclaveMemory()
    {
        void* ret = NULL;
        result = ReturnEnclaveMemory(enclave, &ret);
        CheckResult(result, "ReturnEnclaveMemory()");
        OE_TEST(ret != NULL);
        printf("=== passed ReturnEnclaveMemory()\n");
        // Uncomment to cause intentional seg-fault: 
        // memset(ret, 0, 1);
    }

    // TestBufferCopy(): 1
    {
        char buf[4];
        result = TestBufferCopy(enclave, buf, "ABC", sizeof(buf), false);
        CheckResult(result, "TestBufferCopy(): 1");
        OE_TEST(strcmp(buf, "ABC") == 0);
        printf("=== passed TestBufferCopy(): 1\n");
    }

    // TestBufferCopy(): 2
    {
        char buf[4];
        result = TestBufferCopy(enclave, buf, "ABC", sizeof(buf), true);
        OE_TEST(result == OE_OK);
        printf("=== passed TestBufferCopy(): 2\n");
    }

    printf("=== passed passed all tests (tester)\n");

    CheckResult(OE_TerminateEnclave(enclave), "OE_TerminateEnclave");

    return 0;
}
