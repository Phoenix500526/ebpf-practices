#include <uapi/linux/ptrace.h>

// define data structure
struct data_t {
    u32 uid;
    char command[64];
};
BPF_PERF_OUTPUT(events);

// define uretprobe hook function
int bash_read(struct pt_regs *ctx) {
    // check id
    struct data_t data = {};
    data.uid = bpf_get_current_uid_gid();

    // grab retval from PT_REGS_RC(ctx)
    bpf_probe_read_user(&data.command, sizeof(data.command), (void*)PT_REGS_RC(ctx));

    // submit perf events
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}