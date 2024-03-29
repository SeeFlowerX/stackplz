typedef unsigned long uint64_t;

const char* get_stack(char* dl_path, char* map_buffer, void* opt, void* regs_buf, void* stack_buf);
const char* get_stackv2(char* dl_path, int pid, void* opt, void* regs_buf, void* stack_buf);