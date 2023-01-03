// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 Jacky Yin */
#ifndef __OPENSSL_H
#define __OPENSSL_H

struct ossl_event {
    int type;
    int rec_version;
    unsigned long length;
    unsigned char rseq[8];
    unsigned char riv[16];
    unsigned char wiv[16];
    unsigned char cats[64];
    unsigned char sats[64];
    unsigned char data[2048];
};


#endif /* __OPENSSL_H */
