/* sha512.h - LibreSUM's SHA2-512 Header
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

#ifndef __SHA512_H__
#define __SHA512_H__

#include "base_types.h"

typedef struct {
    hash_ctx_t common;
    uint64_t blk[16];
    uint32_t pos;
    uint64_t tot;
} sha512_ctx_t;

///--- Prototypes
hash_ctx_t* sha512_ctx_new(void);
void sha512_ctx_free(hash_ctx_t *ctx);

rv_t sha512_initialize(hash_ctx_t *ctx);
rv_t sha512_update(hash_ctx_t *ctx, uint8_t *data, uint64_t len);
rv_t sha512_finalize(hash_ctx_t *ctx);

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

/*
 * Note: This requires a 64-bit CPU...Need to fix this and remove the
 * requirement.
 */

#define CH(x,y,z)   ((x&y)^(~x&z))
#define MAJ(x,y,z)  ((x&y)^(x&z)^(y&z))
#define ROTR(n,x)   ((x>>n)|(x<<(64-n)))
#define CS0(x)      (ROTR(28,x) ^ ROTR(34,x) ^ ROTR(39,x))
#define CS1(x)      (ROTR(14,x) ^ ROTR(18,x) ^ ROTR(41,x))
#define SS0(x)      (ROTR(1,x) ^ ROTR(8,x) ^ (x >> 7))
#define SS1(x)      (ROTR(19,x) ^ ROTR(61,x) ^ (x >> 6))
#endif //_SHA512_H__
