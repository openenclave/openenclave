#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include "test.h"

struct e {
	char *k;
	int v;
};

static int count;
static void *root;
static struct e tab[100];
static struct e *cur = tab;

static int cmp(const void *a, const void *b)
{
	return strcmp(((struct e*)a)->k, ((struct e*)b)->k);
}

static int wantc = 'a';
static void act(const void *node, VISIT v, int d)
{
	struct e *e = *(void**)node;

	if (v == preorder)
		if (e->k[0] < wantc)
			t_error("preorder visited node \"%s\" before \"%c\"\n", e->k, wantc);
	if (v == endorder)
		if (e->k[0] > wantc)
			t_error("endorder visited node \"%s\" after \"%c\"\n", e->k, wantc);
	if (v == postorder)
		if (e->k[0] != wantc)
			t_error("postorder visited node \"%s\", wanted \"%c\"\n", e->k, wantc);
	if (v == leaf)
		if (e->k[0] != wantc)
			t_error("visited leaf node \"%s\", wanted \"%c\"\n", e->k, wantc);
	if (v == postorder || v == leaf)
		wantc++;
}

static const void *parent;
static char *searchkey;
static void getparent(const void *node, VISIT v, int d)
{
	static const void *p;
	struct e *e = *(void**)node;

	if (v == preorder || v == leaf)
		if (strcmp(searchkey, e->k) == 0)
			parent = p;
	if (v == preorder || v == postorder)
		p = node;
}

struct e *get(char *k)
{
	void **p = tfind(&(struct e){.k = k}, &root, cmp);
	if (!p) return 0;
	return *p;
}

struct e *set(char *k, int v)
{
	void **p;
	cur->k = k;
	cur->v = v;
	if (!get(k))
		count++;
	p = tsearch(cur++, &root, cmp);
	if (!p || strcmp(((struct e*)*p)->k, k) != 0)
		t_error("tsearch %s %d failed\n", k, v);
	if (!p) {
		count--;
		return 0;
	}
	return *p;
}

void *del(char *k)
{
	void *p = tdelete(&(struct e){.k = k}, &root, cmp);
	if (p)
		count--;
	return p;
}

int main() {
	struct e *e;
	void *p;

	set("f", 6);
	set("b", 2);
	set("c", 3);
	set("e", 5);
	set("h", 8);
	set("g", 7);
	set("a", 1);
	set("d", 4);

	e = get("a");
	if (!e || e->v != 1)
		t_error("tfind a failed\n");
	if (get("z"))
		t_error("tfind z should fail\n");
	e = set("g", 9);
	if (e && e->v != 7)
		t_error("tsearch g 9 returned data %d, wanted 7\n", e->v);
	e = set("g", 9);
	if (e && e->v != 7)
		t_error("tsearch g 9 returned data %d, wanted 7\n", e->v);
	e = set("i", 9);
	if (e && e->v != 9)
		t_error("tsearch i 9 returned data %d, wanted 9\n", e->v);
	if (del("foobar"))
		t_error("tdelete foobar should fail\n");

	twalk(root, act);
	if (wantc!='j')
		t_error("twalk did not visit all nodes (wanted 'j' got '%c')\n", wantc);
	searchkey = "h";
	twalk(root, getparent);
	if (parent == 0)
		t_error("twalk search for key \"%s\" failed\n", searchkey);
	p = del("h");
	if (p != parent)
		t_error("tdelete h failed to return parent (got %p wanted %p)\n", p, parent);

	e = *(void**)root;
	if (!del(e->k))
		t_error("tdelete root \"%s\" failed (returned 0)\n", e->k);

	for (; count; count--) {
		e = *(void**)root;
		if (!tdelete(e, &root, cmp))
			t_error("tdelete k=%s failed during destruction\n", e->k);
	}
	if (root)
		t_error("tree destruction failed: root is nonzero %p\n", root);

	return t_status;
}
