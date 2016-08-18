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

typedef struct {
    hash_ctx_t common;
    uint32_t blk[16];
    uint32_t pos;
    uint64_t tot;
} sha256_ctx_t;

///--- Prototypes
hash_ctx_t* sha256_ctx_new(hash_algo_t *algo);
void sha256_ctx_free(hash_ctx_t *ctx);

rv_t sha256_initialize(hash_ctx_t *ctx);
rv_t sha256_update(hash_ctx_t *ctx, uint8_t *data, uint64_t len);
rv_t sha256_finalize(hash_ctx_t *ctx);

void sha256_print(hash_ctx_t *ctx, const char *fname);
void sha256_print_bsd(hash_ctx_t *ctx, const char *fname);

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
#endif //_SHA2_H__
