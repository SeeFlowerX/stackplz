#include "load_so.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef const char* (*FPTR)(char*, void*, void*, void*);
FPTR fptr = NULL;
int has_dlopen = 0;

const char* get_stack(char* dl_path, char* map_buffer, void* opt, void* regs_buf, void* stack_buf)
{
    // printf("[get_stack], has_dlopen:%d\n", has_dlopen);
    // fflush(stdout);
    if (has_dlopen == 1) {
        return (*fptr)(map_buffer, opt, regs_buf, stack_buf);
    }
    
    void* handle;
    // char dl_path[] = "/data/local/tmp/preload_libs";

    char full_path[256];
    sprintf(full_path, "%s/%s", dl_path, "libbase.so");
    handle = dlopen(full_path, RTLD_NOW);
    // printf("enter, step:%d %s handle:%d\n", 0, full_path, handle==NULL);
    // fflush(stdout);

    sprintf(full_path, "%s/%s", dl_path, "liblzma.so");
    handle = dlopen(full_path, RTLD_NOW);
    // printf("enter, step:%d %s handle:%d\n", 0, full_path, handle==NULL);
    // fflush(stdout);

    sprintf(full_path, "%s/%s", dl_path, "libunwindstack.so");
    handle = dlopen(full_path, RTLD_NOW);
    // printf("enter, step:%d %s handle:%d\n", 1, full_path, handle==NULL);
    // fflush(stdout);

    sprintf(full_path, "%s/%s", dl_path, "libstackplz.so");
    handle = dlopen(full_path, RTLD_NOW);
    // printf("enter, step:%d %s handle:%d\n", 2, full_path, handle==NULL);
    // fflush(stdout);

    fptr = (FPTR)dlsym(handle, "StackPlz");
    // printf("enter, step:%d StackPlz fptr:%p\n", 2, &fptr);
    // fflush(stdout);

    if (has_dlopen == 0) {
        has_dlopen = 1;
    }

    return (*fptr)(map_buffer, opt, regs_buf, stack_buf);
}