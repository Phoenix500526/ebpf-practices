// This is a ebpf program, it will be compiled into BPF Bytescode via llvm first and then submit to kernel.

int hello_world(void* ctx) {
    bpf_trace_printk("Hello world");
    return 0;
}