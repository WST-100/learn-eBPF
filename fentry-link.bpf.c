#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename* name)
{
    pid_t pid;
    // const char* filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    // filename = BPF_CORE_READ(name, name);
    bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);

    return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename* name, long ret)
{
    pid_t pid;
    // const char* filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    // filename = BPF_CORE_READ(name, name);
    bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);

    return 0;
}