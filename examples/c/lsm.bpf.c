// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
/* #include <errno.h> */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("lsm/socket_create")
int BPF_PROG(socket_create_handler, int family, int type, int protocol, int kern, int ret)
{
    if (ret != 0)
        return ret;

	bpf_printk("LSM socket_create, family = %d,  type = %d, protocol: %d\n", family, type, protocol);
	return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind_handler, struct socket *sock, struct sockaddr *address, int addrlen, int ret) 
{
    if (ret != 0)
        return ret;

	bpf_printk("LSM socket_bind, addrlen: %d\n", addrlen);
	return 0;
}


SEC("lsm/socket_accept")
int BPF_PROG(socket_accept_handler, struct socket *sock, struct socket *newsock, int ret)
{
    if (ret != 0)
        return ret;

	bpf_printk("LSM socket_accepted...\n");
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect_handler, struct socket *sock, struct sockaddr *address, int addrlen)
{
    return -1;
}

SEC("lsm/socket_getsockopt")
int BPF_PROG(socket_getsockopt_handler, struct socket *sock, int level, int optname, int ret)
{
    if (ret != 0)
        return ret;

	bpf_printk("LSM socket_getsockopt_handler, level: %d, optname: %d\n", level, optname);
	return 0;
}

