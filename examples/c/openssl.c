// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 Jacky Yin */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <openssl/evp.h>
#include "openssl.skel.h"
#include "openssl.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

#define SEQ_NUM_SIZE 8
static void decrypt(unsigned char *ciphertext, size_t ciphertext_len, unsigned char *key, unsigned char *readiv, unsigned char *seq, int rec_version, int type)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[12];
    unsigned char recheader[5];
    int offset;
    unsigned char plaintext[4096];
    int len;
    int lenf;
    int ivlen;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed...\n");
        return;
    }

    /* Initialise the decryption operation. */
    if(!EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, 0)) {
        fprintf(stderr, "EVP_DecryptInit_ex failed...\n");
        goto ERR;
    }

    ivlen = EVP_CIPHER_CTX_iv_length(ctx);
    fprintf(stdout, "key length: %d\n", EVP_CIPHER_CTX_key_length(ctx));
    fprintf(stdout, "iv length: %d\n", ivlen);

    /* if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL)) { */
    /*     fprintf(stderr, "EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_SET_IVLEN) failed...\n"); */
    /*     return; */
    /* } */

    /* Calculate IV */
    offset = ivlen - SEQ_NUM_SIZE;
    memcpy(iv, readiv, offset);
    for (int loop = 0; loop < SEQ_NUM_SIZE; loop++)
        iv[offset + loop] = readiv[offset + loop] ^ seq[loop];

    /* Initialise key and IV */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 0)) {
        fprintf(stderr, "EVP_DecryptInit_ex failed...\n");
        goto ERR;
    }

    /*
     * Calculate AAD
     */
    recheader[0] = (type & 0xFF);
    recheader[1] = ((rec_version >> 8) & 0XFF);
    recheader[2] = ((rec_version) & 0XFF);
    recheader[3] = (((ciphertext_len) >> 8) & 0XFF);
    recheader[4] = ((ciphertext_len) & 0XFF);
    fprintf(stdout, "recheader: %02X, %02X, %02X, %02X, %02X\n", recheader[0], recheader[1], recheader[2], recheader[3], recheader[4]);

    /*
     * Provide the AAD
     */
    if(!EVP_CipherUpdate(ctx, NULL, &len, recheader, sizeof(recheader))) {
        fprintf(stderr, "EVP_DecryptUpdate failed...\n");
        goto ERR;
    }
    fprintf(stdout, "decryption len after AAD: %d\n", len);

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_CipherUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len - EVP_GCM_TLS_TAG_LEN)) {
        fprintf(stderr, "EVP_DecryptUpdate failed...\n");
        goto ERR;
    }
    fprintf(stdout, "decryption len after decrypt: %d\n", len);

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
        EVP_GCM_TLS_TAG_LEN,
        ciphertext + ciphertext_len - EVP_GCM_TLS_TAG_LEN) <= 0)  {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_SET_TAG) failed...\n");
        goto ERR;
    }

    int ret = EVP_CipherFinal_ex(ctx, plaintext + len, &lenf);
    fprintf(stdout, "decryption result: %d, len: %d, lenf: %d\n", ret, len, lenf);
    fprintf(stdout, "%s\n", plaintext);
ERR:
    EVP_CIPHER_CTX_free(ctx);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct ossl_event *e = data;

    printf("rec_version: %d, type: %d\n", e->rec_version, e->type);

    printf("data length: %lu\n", e->length);

    printf("read sequence: \n");
    for (int i = 0; i < 8; i++) {
        printf("%02X ", e->rseq[i]);
    }
    printf("\n");

    printf("read IV: \n");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", e->riv[i]);
    }
    printf("\n");

    printf("client key: \n");
    for (int i = 0; i < 64; i++) {
        printf("%02X ", e->cats[i]);
    }
    printf("\n");

    printf("server key: \n");
    for (int i = 0; i < 64; i++) {
        printf("%02X ", e->sats[i]);
    }
    printf("\n");

    decrypt(e->data, e->length, e->cats, e->riv, e->rseq, e->rec_version, e->type);
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct openssl_bpf *skel;
	int err, exiting = 0;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = openssl_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	err = openssl_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	/* Process events */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
		sleep(1);
	}


cleanup:
	ring_buffer__free(rb);
	openssl_bpf__destroy(skel);
	return -err;
}
