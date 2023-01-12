// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Jacky Yin */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ZSH  (int)((0x7A) | (0x73 << 8) | (0x68 << 16))
#define BASH (int)((0x62) | (0x61 << 8) | (0x73 << 16) | (0x68 << 24))
#define SH   (int)((0x73) | (0x68 << 8))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ZSH  (int)((0x7A << 24) | (0x73 << 16) | (0x68 << 8))
#define BASH (int)((0x62 << 24) | (0x61 << 16) | (0x73 << 8) | (0x68))
#define SH   (int)((0x73 << 24) | (0x68 << 16))
#else
#error Unknown Byte Order...
#endif

#define isshell(prefix) \
    ((int)(prefix) == ZSH || (int)(prefix) == BASH)

/* SEC("uprobe//usr/bin/whois:handle_query") */
/* int BPF_KPROBE(uprobe_whois_handle_query, const char *hserver, const char *hport, const char *query, const char *flags) */
/* { */
/*     char server[32]; */

/*     if (hserver) { */
/*         bpf_probe_read_user(server, sizeof(server), hserver); */
/*         bpf_printk("server: %s", server); */
/*     } */
/* 	return 0; */
/* } */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u32);
} pid_set SEC(".maps");

static int mystrlen(char *buf, int buflen)
{
    int len = 0;
    for (int i = 0; i < buflen; i++) {
        if (buf[i] == '\0')
            break;
        else
            len++;
    }
    return len;
}

struct openat_pre_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long dfd;
    const char *filename;
    unsigned long flags;
    unsigned long mode;
};

/* SEC("tp/syscalls/sys_enter_openat") */
/* int handle_sys_openat(struct openat_pre_ctx *ctx) */
/* { */
/*     char comm[16]; */
/*     long pid; */
/*     int comm_len; */
/*     int comm_prefix; */

/*     bpf_get_current_comm(comm, sizeof(comm)); */
/*     pid = bpf_get_current_pid_tgid(); */
/*     comm_len = strlen(comm); */

/*     if (comm_len > 4) */
/*         return 0; */

/*     comm_prefix = (int)comm; */

/*     if (comm_prefix == ZSH || comm_prefix == BASH || comm_prefix == SH) { */
/*         bpf_printk("[%s][%d] open file: %s\n", comm, pid >> 32, ctx->filename); */
/*     } */
/* 	return 0; */
/* } */

struct openat_post_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long ret;
};

/* SEC("tp/syscalls/sys_exit_openat") */
/* int handle_sys_openat_exit(struct openat_post_ctx *ctx) */
/* { */
/*     char comm[16]; */
/*     long pid; */
/*     int comm_len; */
/*     int comm_prefix; */

/*     bpf_get_current_comm(comm, sizeof(comm)); */
/*     pid = bpf_get_current_pid_tgid(); */
/*     comm_len = strlen(comm); */

/*     if (comm_len > 4) */
/*         return 0; */

/*     comm_prefix = (int)comm; */

/*     if (comm_prefix == ZSH || comm_prefix == BASH || comm_prefix == SH) { */
/*         bpf_printk("[%s][%d] open file ret: %d\n", comm, pid >> 32, ctx->ret); */
/*     } */
/* 	return 0; */
/* } */

struct write_pre_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long fd;
    char *buf;
    size_t count;
};

/* SEC("tp/syscalls/sys_enter_write") */
/* int handle_sys_write(struct write_pre_ctx *ctx) */
/* { */
/*     char comm[16]; */
/*     long pid; */
/*     int comm_len; */
/*     int comm_prefix; */

/*     bpf_get_current_comm(comm, sizeof(comm)); */
/*     pid = bpf_get_current_pid_tgid(); */
/*     comm_len = strlen(comm); */

/*     if (comm_len > 4) */
/*         return 0; */

/*     comm_prefix = (int)comm; */

/*     if (comm_prefix == ZSH || comm_prefix == BASH || comm_prefix == SH) { */
/*         if (ctx->fd == 1) { */
/*             bpf_printk("[%s][%d] write to stdout: %d\n", comm, pid >> 32, ctx->fd); */
/*         } */
/*     } */
/* 	return 0; */
/* } */

struct dup3_pre_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long oldfd;
    unsigned long newfd;
    unsigned long flags;
};

SEC("tp/syscalls/sys_enter_dup3")
int handle_sys_dup3(struct dup3_pre_ctx *ctx)
{
    char comm[16];
    pid_t pid;
    int comm_len;
    int comm_prefix;

    bpf_get_current_comm(comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid() >> 32;
    comm_len = mystrlen(comm, sizeof(comm));

    if (comm_len > 4)
        return 0;

    comm_prefix = *(int *)comm;

    if (isshell(comm_prefix) && ctx->newfd == 1) {
        int val = 1;
	    bpf_map_update_elem(&pid_set, &pid, &val, BPF_NOEXIST);
        /* bpf_printk("[%s][%d] ", comm, pid); */
        /* bpf_printk("dup3 from %d to %d\n", ctx->oldfd, ctx->newfd); */
    }
	return 0;
}

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

SEC("tp/syscalls/sys_enter_execve")
int handle_sys_execve(struct execve_pre_ctx *ctx)
{
    char comm[16];
    char temp_argv[48];
    char exe[8];
    char temp_arg[32];
    pid_t pid;
    int *val;

    pid = bpf_get_current_pid_tgid() >> 32;
    val = bpf_map_lookup_elem(&pid_set, &pid);

    if (!val)
        return 0;

    bpf_probe_read_user(temp_argv, sizeof(temp_argv), ctx->argv);

    const char **argp = (const char **)temp_argv;

    if (*argp) {
        bpf_probe_read_user(exe, sizeof(exe), *argp);
        bpf_printk("exe: %s\n", *argp);
        argp++;
    }

    if (exe[0] != 'w' || exe[1] != 'h' || exe[2] != 'o' || exe[3] != 'i' || exe[4] != 's')
        return 0;

    for (int i = 1; i < 6; i++) {
        if (!*argp)
            break;

        bpf_probe_read_user(temp_arg, sizeof(temp_arg), *argp);
        bpf_printk("arg[%d]: %s\n", i, temp_arg);

        // specify host in whois command
        if (temp_arg[0] == '-' && temp_arg[1] == 'h') {
            /* bpf_printk("[%s][%d] exec file: %s\n", comm, pid, ctx->filename); */
            bpf_printk("capture whois -h xxxxxx > yyyyy");
	        bpf_map_delete_elem(&pid_set, &pid);
        }
        argp++;
    }
	return 0;
}


