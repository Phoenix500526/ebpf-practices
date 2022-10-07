#include <uapi/linux/ptrace.h>


struct data_t {
    char filename[64];
    char function[32];
    u32 lineno; 
};
BPF_PERF_OUTPUT(events);

int print_functions(struct pt_regs *ctx){
    uint64_t argptr;
    struct data_t data = {};
    
    // the first argument is the filename
    bpf_usdt_readarg(1, ctx, &argptr);
    bpf_probe_read_user(&data.filename, sizeof(data.filename), (void *)argptr);

    // the second argument is the function name
    bpf_usdt_readarg(2, ctx, &argptr);
    bpf_probe_read_user(&data.function, sizeof(data.function), (void *)argptr);

    // the final argument is the lineno
    bpf_usdt_readarg(3, ctx, &data.lineno);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}