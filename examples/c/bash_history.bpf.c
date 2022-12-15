// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* A structure which represents a word. */
typedef struct word_desc {
  char *word;		/* Zero terminated string. */
  int flags;		/* Flags associated with this word. */
} WORD_DESC;

/* A linked list of words. */
typedef struct word_list {
  struct word_list *next;
  WORD_DESC *word;
} WORD_LIST;

SEC("uprobe//usr/bin/bash:history_builtin")
int BPF_KPROBE(uprobe_his_builtin, WORD_LIST *list)
{
	/* bpf_printk("history_builtin ENTRY: list = %p", list); */

    if (!list) {
	    bpf_printk("peeking bash history!");
    } else  {
        WORD_LIST ulist;
        WORD_DESC desc;
        char word[10];
        int length = 0;

        bpf_probe_read(&ulist, sizeof(WORD_LIST), (void *)list);
        bpf_probe_read(&desc, sizeof(WORD_DESC), (void *)ulist.word);
        bpf_probe_read_str(word, 10, (void *)desc.word);
        /* bpf_printk("%s", word); */

        for (int i = 0; i < 10; i++) {
            char *cur = word + i;
            if (!(cur && *cur != '\0'))
                break;
            length++;
        }

        if (length == 2 && word[0] == '-' && word[1] == 'c') {
	        bpf_printk("clearing bash history!");
        }
    }
	return 0;
}
