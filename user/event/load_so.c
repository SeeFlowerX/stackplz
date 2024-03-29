#include "load_so.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef const char* (*FPTR)(char*, void*, void*, void*);
FPTR fptr = NULL;

typedef const char* (*FPTRV2)(int, void*, void*, void*);
FPTRV2 fptrv2 = NULL;

int has_dlopen = 0;

void setup(char* dl_path) {

    void* handle;
    char full_path[256];

    sprintf(full_path, "%s/%s", dl_path, "libstackplz.so");
    handle = dlopen(full_path, RTLD_NOW);
    fptr = (FPTR)dlsym(handle, "StackPlz");
    fptrv2 = (FPTRV2)dlsym(handle, "StackPlzV2");

    if (has_dlopen == 0) {
        has_dlopen = 1;
    }
}

const char* get_stack(char* dl_path, char* map_buffer, void* opt, void* regs_buf, void* stack_buf)
{
    if (has_dlopen == 1) {
        return (*fptr)(map_buffer, opt, regs_buf, stack_buf);
    }
    
    setup(dl_path);

    return (*fptr)(map_buffer, opt, regs_buf, stack_buf);
}

const char* get_stackv2(char* dl_path, int pid, void* opt, void* regs_buf, void* stack_buf)
{
    if (has_dlopen == 1) {
        return (*fptrv2)(pid, opt, regs_buf, stack_buf);
    }
    
    setup(dl_path);

    return (*fptrv2)(pid, opt, regs_buf, stack_buf);
}