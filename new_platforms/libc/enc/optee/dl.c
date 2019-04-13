#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>

void *dlopen(const char *filename, int flags) { return NULL; }
int dlclose(void *handle) { return EINVAL; }
char *dlerror(void) { return "Not supported."; }
void *dlsym(void *handle, const char *symbol) { return NULL; }
