// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 Jacky Yin */
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "taskiter.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct taskiter_bpf *skel;
	struct bpf_link *link;
	const char *path = "/sys/fs/bpf/testiter";
	int err = 0;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = taskiter_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	link = bpf_program__attach_iter(skel->progs.dump_task, NULL);
	if (!link) {
		fprintf(stderr, "Failed to create link for iter\n");
		goto cleanup;
	}

	unlink(path);

	err = bpf_link__pin(link, path);
	if (err) {
		fprintf(stderr, "Failed to pin link to fs\n");
		goto cleanup_link;
	}

cleanup_link:
	bpf_link__destroy(link);
cleanup:
	/* Clean up */
	taskiter_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
