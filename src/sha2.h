/* sha2.h - LibreSUM's Sha2 Header
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Charles `sparticvs` Timko
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef __SHA2_H__
#define __SHA2_H__

#include "base_types.h"

// TODO Redefine this struct inheriting from hash_ctx_t...

typedef struct {
    hash_ctx_t common;
    uint32_t blk[16];
    uint32_t pos;
    uint64_t tot;
} sha256_ctx_t;

///--- Prototypes

rv_t sha256_initialize(sha256_ctx_t *ctx);
rv_t sha256_update(sha256_ctx_t *ctx, uint8_t *data, uint64_t len);
rv_t sha256_finalize(sha256_ctx_t *ctx);


typedef struct {
    char *tv;
    uint64_t len;
    uint32_t hash[8];
} testvector_t;

typedef struct {
    FILE *fp;
    uint32_t hash[8];
    char *filename;
    uint32_t flags;
} checkentry_t;

#define CH(x,y,z)   ((x&y)^(~x&z))
#define MAJ(x,y,z)  ((x&y)^(x&z)^(y&z))
#define ROTR(n,x)   ((x>>n)|(x<<(32-n)))
#define CS0(x)      (ROTR(2,x) ^ ROTR(13,x) ^ ROTR(22,x))
#define CS1(x)      (ROTR(6,x) ^ ROTR(11,x) ^ ROTR(25,x))
#define SS0(x)      (ROTR(7,x) ^ ROTR(18,x) ^ (x >> 3))
#define SS1(x)      (ROTR(17,x) ^ ROTR(19,x) ^ (x >> 10))
#define NESSIE_TV_MAX 8
const testvector_t NESSIE_TV[] = {
    { // Set 1, Vector 0
        .tv = "",
        .len = 0,
        .hash = { 
            0xE3B0C442, 0x98FC1C14, 0x9AFBF4C8, 0x996FB924,
            0x27AE41E4, 0x649B934C, 0xA495991B, 0x7852B855 }
    },
    { // Set 1, Vector 1
        .tv = "a",
        .len = 1,
        .hash = {
            0xCA978112, 0xCA1BBDCA, 0xFAC231B3, 0x9A23DC4D,
            0xA786EFF8, 0x147C4E72, 0xB9807785, 0xAFEE48BB }
    },
    { // Set 1, Vector 2
        .tv = "abc",
        .len = 3,
        .hash = {
            0xBA7816BF, 0x8F01CFEA, 0x414140DE, 0x5DAE2223,
            0xB00361A3, 0x96177A9C, 0xB410FF61, 0xF20015AD }
    },
    { // Set 1, Vector 3
        .tv = "message digest",
        .len = 14,
        .hash = {
            0xF7846F55, 0xCF23E14E, 0xEBEAB5B4, 0xE1550CAD,
            0x5B509E33, 0x48FBC4EF, 0xA3A1413D, 0x393CB650 }
    },
    { // Set 1, Vector 4
        .tv = "abcdefghijklmnopqrstuvwxyz",
        .len = 26,
        .hash = {
            0x71C480DF, 0x93D6AE2F, 0x1EFAD144, 0x7C66C952,
            0x5E316218, 0xCF51FC8D, 0x9ED832F2, 0xDAF18B73 }
    },
    { // Set 1, Vector 5
        .tv = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        .len = 56,
        .hash = {
            0x248d6a61, 0xd20638b8, 0xe5c02693, 0x0c3e6039,
            0xa33ce459, 0x64ff2167, 0xf6ecedd4, 0x19db06c1 }
    },
    { // Set 1, Vector 6
        .tv = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        .len = 62,
        .hash = {
            0xDB4BFCBD, 0x4DA0CD85, 0xA60C3C37, 0xD3FBD880,
            0x5C77F15F, 0xC6B1FDFE, 0x614EE0A7, 0xC8FDB4C0 }
    },
    { // Set 1, Vector 7
        .tv = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        .len = 80,
        .hash = {
            0xF371BC4A, 0x311F2B00, 0x9EEF952D, 0xD83CA80E,
            0x2B60026C, 0x8E935592, 0xD0F9C308, 0x453C813E }
    },
    /** Skipping remainder, as the last one is 1 million `a's **/
};
#endif //_SHA2_H__
