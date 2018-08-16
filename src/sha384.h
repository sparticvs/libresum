/* sha384.h - LibreSUM's SHA2-384 Header
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

#ifndef __SHA384_H__
#define __SHA384_H__

#include "base_types.h"

#define SHA384_WORD_BIT_SZ          64
#define SHA384_WORD_SZ              (SHA384_WORD_BIT_SZ / 8)
#define SHA384_HASH_WORD_LEN        6

#define SHA384_BLOCK_BIT_LEN        1024
#define SHA384_BLOCK_LEN            (SHA384_BLOCK_BIT_LEN / 8)
#define SHA384_BLOCK_WORD_LEN       (SHA384_BLOCK_LEN / SHA384_WORD_SZ)

#define SHA384_SCHED_WORD_LEN       80

#define SHA384_MSG_LEN_BIT_LEN      128
#define SHA384_MSG_LEN_LEN          (SHA384_MSG_LEN_BIT_LEN / 8)

#define SHA384_LAST_BLOCK_BIT_MAX   (SHA384_BLOCK_BIT_LEN - SHA384_MSG_LEN_BIT_LEN)
#define SHA384_LAST_BLOCK_MAX       (SHA384_LAST_BLOCK_BIT_MAX / 8)

typedef struct {
    hash_ctx_t common;
    uint64_t blk[SHA384_BLOCK_WORD_LEN];
    uint64_t pos;
    uint64_t tot;
} sha384_ctx_t;

///--- Prototypes
hash_ctx_t* sha384_ctx_new(hash_algo_t *algo);
void sha384_ctx_free(hash_ctx_t *ctx);

rv_t sha384_initialize(hash_ctx_t *ctx);
rv_t sha384_update(hash_ctx_t *ctx, uint8_t *data, uint64_t len);
rv_t sha384_finalize(hash_ctx_t *ctx);

void sha384_print(hash_ctx_t *ctx, const char *fname);
void sha384_print_bsd(hash_ctx_t *ctx, const char *fname);

rv_t sha384_parse(const char *str, checkentry_t *entry);
bool sha384_compare(hash_ctx_t *ctx, checkentry_t *entry);

#endif //_SHA384_H__
