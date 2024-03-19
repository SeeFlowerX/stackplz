#include "load_so.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef const char* (*FPTR)(char*, void*, void*, void*);
FPTR fptr = NULL;
int has_dlopen = 0;

const char* get_stack(char* dl_path, char* map_buffer, void* opt, void* regs_buf, void* stack_buf)
{
    if (has_dlopen == 1) {
        return (*fptr)(map_buffer, opt, regs_buf, stack_buf);
    }
    
    void* handle;
    char full_path[256];

    sprintf(full_path, "%s/%s", dl_path, "libstackplz.so");
    handle = dlopen(full_path, RTLD_NOW);
    fptr = (FPTR)dlsym(handle, "StackPlz");

    if (has_dlopen == 0) {
        has_dlopen = 1;
    }

    return (*fptr)(map_buffer, opt, regs_buf, stack_buf);
}