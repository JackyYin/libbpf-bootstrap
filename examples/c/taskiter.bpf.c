#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (task) {
        BPF_SEQ_PRINTF(seq, "%8d %8d %8d\n", task->tgid, task->pid, task->self_exec_id);
    }
    return 0;
}
