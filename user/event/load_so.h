typedef unsigned long uint64_t;

struct UnwindBuf {
    uint64_t abi;
    uint64_t regs[33];
    uint64_t size;
    char data[16384];
    uint64_t dyn_size;
};

const char* get_stack(int pid, uint64_t reg_mask, void* unwind_buf);