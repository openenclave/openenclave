#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <openenclave/bits/search.h>

typedef struct _Node Node;

struct _Node
{
    struct OE_tnode base;
    Node* next;
    int value;
};

static void* _OE_malloc_result;

static size_t _mallocs;
static size_t _frees;

static void* _malloc(size_t size)
{
    _mallocs++;
    return _OE_malloc_result;
}

static void _free(void* ptr)
{
    _frees++;
}

static void *MakeNode(int value)
{
   Node* node = calloc(1, sizeof(Node));

   if (!node)
        return NULL;

    _mallocs++;

   node->base.key = &node->base;
   node->value = value;

   return node;
}

static int compare(const void* pa, const void *pb)
{
    const Node* lhs = (const Node*)pa;
    const Node* rhs = (const Node*)pb;

    if (lhs->value < rhs->value)
        return -1;

    if (lhs->value > rhs->value)
        return 1;

    return 0;
}

static int _sum;

void Dump(Node* node)
{
    printf("Node: %p ", node);

    for (Node* p = node; p; p = (Node*)p->next)
    {
        printf("%d ", p->value);
        _sum += p->value;
    }
        
    printf("\n");
}

void DumpTree(Node* node)
{
    if (node->base.left)
        DumpTree((Node*)node->base.left);

    Dump(node);

    if (node->base.right)
        DumpTree((Node*)node->base.right);
}

static void _free_node(void *nodep)
{
    Node* node = (Node*)nodep;
    Node* next = NULL;

    for (Node* p = node; p; p = next)
    {
        next = p->next;
        free(p);
        _frees++;
    }
}

int main(int argc, const char* argv[])
{
    void* root = NULL;
    size_t i;
    int sum = 0;

    srand(time(NULL));

    for (i = 0; i < 64; i++) 
    {
        int value = rand() % 16;
        sum += value;

        Node* node = MakeNode(value);
        assert(node != NULL);

        _OE_malloc_result = node;
        Node* ret = OE_tsearch(&node->base, &root, compare, _malloc);
        _OE_malloc_result = NULL;

        if (ret != node)
        {
            node->next = ret->next;
            ret->next = node;
        }
    }

    DumpTree((Node*)root);
    assert(sum == _sum);

    OE_tdestroy(root, _free_node, _free);
    assert(_mallocs == _frees);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
