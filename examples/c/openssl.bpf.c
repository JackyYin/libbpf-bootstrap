// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Jacky Yin */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "openssl.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

    unsigned char cats[64];

# define SSL3_VERSION                    0x0300
# define TLS1_VERSION                    0x0301
# define TLS1_1_VERSION                  0x0302
# define TLS1_2_VERSION                  0x0303
# define TLS1_3_VERSION                  0x0304
# define DTLS1_VERSION                   0xFEFF
# define DTLS1_2_VERSION                 0xFEFD
# define DTLS1_BAD_VER                   0x0100

#define OFFSETOF_SSL_ST_VERSION (0)        // version
#define OFFSETOF_SSL_ST_C_ATS (1860)       // client_app_traffic_secret
#define OFFSETOF_SSL_ST_S_ATS (1924)       // server_app_traffic_secret
#define OFFSETOF_SSL_ST_READ_IV (2128)     // read_iv
#define OFFSETOF_SSL_ST_WRITE_IV (2176)    // write_iv
#define OFFSETOF_SSL_ST_RREC_VER (4776)    // rlayer.rrec.rec_version
#define OFFSETOF_SSL_ST_RREC_TYPE (4780)   // rlayer.rrec.type
#define OFFSETOF_SSL_ST_RREC_LENGTH (4784) // rlayer.rrec.length
#define OFFSETOF_SSL_ST_RREC_DATA (4808)   // rlayer.rrec.data
#define OFFSETOF_SSL_ST_RREC_INPUT (4816)  // rlayer.rrec.input
#define OFFSETOF_SSL_ST_RSEQ (7416)        // rlayer.read_sequence
#define OFFSETOF_SSL_ST_WSEQ (7424)        // rlayer.write_sequence

/* static void *sslptr = NULL; */

/* SEC("uprobe//home/jackyyin/Projects/openssllab/libssl.so.3:SSL_connect") */
/* int BPF_KPROBE(uprobe_SSL_connect, void *ssl) */
/* { */
/*     int version; */
/*     void *tmp; */

/*     sslptr = ssl; */
/*     tmp = ((void *)ssl + OFFSETOF_SSL_ST_VERSION); */
/*     bpf_probe_read_user(&version, sizeof(int), tmp); */

/*     if (version == TLS1_3_VERSION) { */
/*         bpf_printk("SSL_connect with TLS 1.3"); */
/*     } else { */
/*         bpf_printk("SSL_connect with unknown version"); */
/*     } */
/* } */

/* SEC("uretprobe//home/jackyyin/Projects/openssllab/libssl.so.3:SSL_connect") */
/* int BPF_KRETPROBE(uretprobe_SSL_connect, int ret) */
/* { */
/*     struct ossl_event *e; */
/*     void *tmp; */

/* 	/1* reserve sample from BPF ringbuf *1/ */
/* 	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0); */
/* 	if (!e) */
/* 		return 0; */

/*     tmp = ((void *)sslptr + OFFSETOF_SSL_ST_VERSION); */
/*     bpf_probe_read_user(&(e->version), sizeof(int), tmp); */

/*     bpf_printk("SSL_connect ret version: %d", e->version); */

/*     if (e->version == TLS1_3_VERSION) { */
/*         tmp = ((void *)sslptr + OFFSETOF_SSL_ST_C_ATS); */
/*         bpf_probe_read_user(e->cats, 64, tmp); */
/*         tmp = ((void *)sslptr + OFFSETOF_SSL_ST_S_ATS); */
/*         bpf_probe_read_user(e->sats, 64, tmp); */
/*     } */
/* 	bpf_ringbuf_submit(e, 0); */
/* } */

SEC("uprobe//home/jackyyin/Projects/openssllab/libssl.so.3:SSL_read")
int BPF_KPROBE(uprobe_SSL_read, void *ssl, void *buf, int num)
{
    bpf_printk("SSL_read with length: %d...", num);
    return 0;

    /* struct ossl_event *e; */
    /* void *tmp; */

	/* e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0); */
	/* if (!e) */
		/* return 0; */

    /* tmp = ((void *)ssl + OFFSETOF_SSL_ST_VERSION); */
    /* bpf_probe_read_user(&(e->version), sizeof(int), tmp); */

    /* bpf_printk("SSL_read version: %d", e->version); */

    /* if (e->version == TLS1_3_VERSION) { */
    /*     tmp = ((void *)ssl + OFFSETOF_SSL_ST_C_ATS); */
    /*     bpf_probe_read_user(e->cats, 64, tmp); */
    /*     tmp = ((void *)ssl + OFFSETOF_SSL_ST_S_ATS); */
    /*     bpf_probe_read_user(e->sats, 64, tmp); */
    /* } */
	/* bpf_ringbuf_submit(e, 0); */
}

/* SEC("uprobe//home/jackyyin/Projects/openssllab/libssl.so.3:SSL_write") */
/* int BPF_KPROBE(uprobe_SSL_write, void *ssl, const void *buf, int num) */
/* { */
/*     bpf_printk("SSL_write with length: %d...", num); */
/* } */

SEC("uprobe//home/jackyyin/Projects/openssllab/libssl.so.3:tls13_enc")
int BPF_KPROBE(uprobe_tls13_enc, void *ssl, void *recs, unsigned long n_recs, int sending)
{
    int version;
    void *tmp = NULL;
    struct ossl_event *e;

    tmp = ((void *)ssl + OFFSETOF_SSL_ST_VERSION);
    bpf_probe_read_user(&(version), sizeof(version), tmp);

    if (version == TLS1_3_VERSION && !sending) {
	    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

        if (!e)
            return 0;

        tmp = ((void *)ssl + OFFSETOF_SSL_ST_RREC_LENGTH);
        bpf_probe_read_user(&(e->length), sizeof(e->length), tmp);
        bpf_printk("rrec data length: %lu", e->length);

        if (e->length > 2048) {
            bpf_printk("receive huge rrec data, discard...");
            bpf_ringbuf_discard(e, 0);
        } else {
            tmp = ((void *)ssl + OFFSETOF_SSL_ST_RREC_INPUT);
            bpf_probe_read_user(&(e->data), e->length, tmp);

            tmp = ((void *)ssl + OFFSETOF_SSL_ST_RREC_VER);
            bpf_probe_read_user(&(e->rec_version), sizeof(e->rec_version), tmp);

            tmp = ((void *)ssl + OFFSETOF_SSL_ST_RREC_TYPE);
            bpf_probe_read_user(&(e->type), sizeof(e->type), tmp);

            tmp = ((void *)ssl + OFFSETOF_SSL_ST_C_ATS);
            bpf_probe_read_user(e->cats, 64, tmp);

            tmp = ((void *)ssl + OFFSETOF_SSL_ST_S_ATS);
            bpf_probe_read_user(e->sats, 64, tmp);

            tmp = ((void *)ssl + OFFSETOF_SSL_ST_RSEQ);
            bpf_probe_read_user(&(e->rseq), sizeof(e->rseq), tmp);

            tmp = ((void *)ssl + OFFSETOF_SSL_ST_READ_IV);
            bpf_probe_read_user(&(e->riv), sizeof(e->riv), tmp);

            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}
