// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct execve_pre_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    const char * filename;
    const char ** argv;
    const char ** envp;
};

struct execve_post_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    long ret;
};

SEC("tp/syscalls/sys_enter_execve")
int handle_tp_enter(struct execve_pre_ctx *ctx)
{
    char temp_argv[100];
    char temp[16];
	bpf_printk("exec file: %s, argv: %p\n", ctx->filename, ctx->argv);
    bpf_probe_read(temp_argv, sizeof(char *) * 10, ctx->argv);

    const char **argp = temp_argv;
    for (int i = 0; i < 5; i++) {
        if (*argp) {
            bpf_probe_read(temp, sizeof(temp), *argp);
            bpf_printk("argv[%d]: %s\n", i, temp);
            argp ++;
        }
    }

	return 0;
}

SEC("tp/syscalls/sys_exit_execve")
int handle_tp_exit(struct execve_post_ctx *ctx)
{
	bpf_printk("exec ret: %ld.\n", ctx->ret);
	return 0;
}
