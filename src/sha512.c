/* sha512sum.c - Calculate the SHA512 sum of a file.
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

    usage: sha512sum [OPTION]... [FILE]...

    Print or check SHA512 (512-bit) checksums.
    With no FILE, or when FILE is -, read standard input.

    -b, --binary         read in binary mode
    -c, --check          read SHA5126 sums from the FILEs and check them
        --tag            create a BSD-style checksum
    -t, --text           read in text mode (default)

    The following three options are useful only when verifying checksums:
        --quiet          don't print OK for each successfully verified file
        --status         don't output anything, status code shows success
    -w, --warn           warn about improperly formatted checksum lines

        --strict         with --check, exit non-zero for any invalid input
        --help     display this help and exit
        --version  output version information and exit

   The sums are computed as described in FIPS-180-4.  When checking, the input
   should be a former output of this program.  The default mode is to print
   a line with checksum, a character indicating input mode ('*' for binary,
   space for text), and name for each FILE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#if __APPLE__ && __MACH__
#include <libkern/OSByteOrder.h>
#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#else
#include <endian.h>
#endif
#include "base_types.h"
#include "sha512.h"

#define ARRAY_SZ    1024*32

/*
 * Note
 *
 * The intent is to mimic as much as possible the Perl script and it's output.
 * However, we will also support other output types, but we may require a
 * flag to do so.
 */

// This is logical, as you can fscanf and have all the data you need
#define DEFAULT_OUTPUT  "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x %c%s\n"
// The %c is to output a `*' if the hash was done in binary mode
// but on *NIX systems, this doesn't really matter as binary mode is 
// the same as text mode. We do, however, want to implement this
// correctly... There are other character outputs as well, need to
// investigate what those are and what we need to do for them.
#define BSD_OUTPUT "SHA512 (%s) = %08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n"

const uint64_t H512[] = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
};

const uint64_t K512[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

#define SHA512_WORD_BIT_SZ      64
#define SHA512_WORD_SZ          SHA512_WORD_BIT_SZ / 8
#define SHA512_HASH_WORD_LEN    16
#define SHA512_BLOCK_BIT_LEN    1024
#define SHA512_BLOCK_LEN        SHA512_BLOCK_LEN / 8

#define SHA512_MSG_LEN_BIT_LEN  128
#define SDA512_MSG_LEN_LEN      SHA512_MSG_LEN_BIT_LEN / 8

const int16_t blk_sz = 128;
const int16_t last_blk_sz = 112;

hash_ctx_t* sha512_ctx_new(hash_algo_t *algo) {
    sha512_ctx_t *ctx = NULL;

    ctx = malloc(sizeof(sha512_ctx_t));
    if(NULL == ctx) {
        return NULL;
    }

    ctx->common.algo = algo;

    ctx->common.hash = malloc(SHA512_WORD_SZ * SHA512_HASH_WORD_LEN);
    if(NULL == ctx->common.hash) {
        free(ctx);
        return NULL;
    }

    ctx->common.len = SHA512_HASH_WORD_LEN;

    return &(ctx->common);
}

void sha512_ctx_free(hash_ctx_t *ctx) {
    sha512_ctx_t *sha_ctx = (sha512_ctx_t*)ctx;
    if(NULL != sha_ctx) {
        free(sha_ctx->common.hash);
        free(sha_ctx);
    }
}

/*
 * SHA2-512 Message Schedule
 *
 * This will prepare the message schedule as per the FIPS standard
 *
 * @param sched     640-bytes allocation for working in place on the schedule
 * @param msg       128-bytes of the message
 *
 * @return Returns an RV_ value
 */
rv_t __sha512_msg_sched(uint64_t *sched, const uint64_t const *msg) {
    rv_t retval = RV_UNKNOWN;

    if (NULL == sched || NULL == msg) {
        retval = RV_INVALARG;
    }

    if (RV_UNKNOWN == retval) {
        uint32_t j = 0;
        for(j = 0; j < 16; j++) {
            sched[j] = msg[j];
        }

        for(j = 16; j < 80; j += 2) {
            // 2 at a time means less overhead
            sched[j] = SS1(sched[j-2]) + sched[j-7] + SS0(sched[j-15]) + sched[j-16];
            sched[j+1] = SS1(sched[j-1]) + sched[j-6] + SS0(sched[j-14]) + sched[j-15];
        }

        retval = RV_SUCCESS;
    }

    return retval;
}

/* SHA2-512 Computation
 *
 * Computes the SHA-512 hash on block boundary and is supplied the H(i-1)
 * This isn't intended to be exposed and could be shared between algos.
 *
 * @param hash      512-bit hash, updated in place
 * @param msg       128-bytes of the message
 *
 * @return Returns an RV_ value
 */
rv_t __sha512_compute(uint64_t *hash, const uint64_t const *msg) {
    rv_t retval = RV_UNKNOWN;
    if (NULL == hash || NULL == msg) {
        retval = RV_INVALARG;
    }
    uint64_t a, b, c, d, e, f, g, h, T1, T2, j;
    uint64_t W[80] = {0};

    if (RV_UNKNOWN == retval) {
        // Load registers
        a = hash[0];
        b = hash[1];
        c = hash[2];
        d = hash[3];
        e = hash[4];
        f = hash[5];
        g = hash[6];
        h = hash[7];
    }

    // Compute the Message Schedule for this block
    if (RV_SUCCESS != __sha512_msg_sched(W, msg)) {
        retval = RV_NESTEDERR;
    }

    if (RV_UNKNOWN == retval) {
        for(j = 0; j < 80; j++) {
            T1 = h + CS1(e) + CH(e, f, g) + K512[j] + W[j];
            T2 = CS0(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // Is there some way to optimize this?
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;

        retval = RV_SUCCESS;
    }

    return retval;
}

/* SHA512 Initialize
 *
 * @param ctx       Pointer to sha-512 context to initialize
 *
 * @return Returns an RV_ value.
 */
rv_t sha512_initialize(hash_ctx_t *hash_ctx) {
    rv_t rv = RV_UNKNOWN;

    if (NULL == hash_ctx) {
        rv = RV_INVALARG;
    } else {
        sha512_ctx_t *ctx = (sha512_ctx_t*)hash_ctx;

        // We are in a stable state, initialize
        ctx->common.hash[0] = 0x6a09e667f3bcc908;
        ctx->common.hash[1] = 0xbb67ae8584caa73b;
        ctx->common.hash[2] = 0x3c6ef372fe94f82b;
        ctx->common.hash[3] = 0xa54ff53a5f1d36f1;
        ctx->common.hash[4] = 0x510e527fade682d1;
        ctx->common.hash[5] = 0x9b05688c2b3e6c1f;
        ctx->common.hash[6] = 0x1f83d9abfb41bd6b;
        ctx->common.hash[7] = 0x5be0cd19137e2179;

        // Clear out the blk
        memset(ctx->blk, 0, SHA512_WORD_SZ * SHA512_HASH_WORD_LEN);

        ctx->pos = 0;
        ctx->tot = 0;

        // Ok, we got here, set the RV
        rv = RV_SUCCESS;
    }

    return rv;
}

static inline void __blk_htobe(uint64_t *data) {
    // We assume block size
    uint8_t i;
    for (i = 0; i < 16; i++) {
        data[i] = htobe64(data[i]);
    }
}


/* SHA256 Update
 *
 * @param ctx       Pointer to sha-256 context to operate on
 * @param data      Pointer to data blob to bring into the hash
 * @param len       Length of the data that is being updated in bytes
 *
 * @return Returns an RV_ value
 */
rv_t sha512_update(hash_ctx_t *hash_ctx, uint8_t *data, uint64_t len) {
    rv_t rv = RV_UNKNOWN;

    if (NULL == hash_ctx || NULL == data) {
        rv = RV_INVALARG;
    } else {
        sha512_ctx_t *ctx = (sha512_ctx_t*)hash_ctx;
        // 1. If ctx->pos > 0, fill blk up and process, memmove data and change
        // length
        if (ctx->pos > 0) {
            uint8_t avail = 64 - ctx->pos;
            if (len < avail) {
                avail = len;
            }
            memcpy((void*)ctx->blk+ctx->pos, (void*)data, avail);
            ctx->pos += avail;

            memmove((void*)data+avail, (void*)data, avail);
            len -= avail;

            if (ctx->pos == 64) {
                __blk_htobe(ctx->blk);
                __sha512_compute(ctx->common.hash, ctx->blk);
                ctx->tot += avail;

                memset(ctx->blk, 0, 16 * sizeof(uint32_t));
                ctx->pos = 0;
            }
        }
        
        // 2. If len % 64 != 0, move extra into ctx->blk
        if (len > 0 && len % 64 != 0) {
            uint8_t rem = len % 64;
            // If there was enough to process a block, we would have
            memcpy((void*)ctx->blk+ctx->pos, (void*)data+len-rem, rem);
            // No longer part of the length
            len -= rem;
            // Increase pos by rem
            ctx->pos += rem;
            ctx->tot += rem;
        }
        
        // 3. Compute the data in chunks of 64-bytes
        uint64_t cnt;
        for (cnt = 0; cnt < len / 64; cnt++) {
            __blk_htobe((void*)data+(64*cnt));
            __sha512_compute(ctx->common.hash, (void*)data+(64*cnt));
            ctx->tot += 64;
        }

        // 4. Set return value
        rv = RV_SUCCESS;
    }

    return rv;
}

/* SHA-512 Finalize
 *
 * Finish the SHA-512 computation. This pads the blocks correctly and does the
 * final update to the hash.
 *
 * @param ctx       Pointer to the sha-512 context to finalize
 *
 * @return Returns an RV_ value
 */
rv_t sha512_finalize(hash_ctx_t *hash_ctx) {
    rv_t rv = RV_UNKNOWN;

    if (NULL == hash_ctx) {
        rv = RV_INVALARG;
    } else {
        sha512_ctx_t *ctx = (sha512_ctx_t*)hash_ctx;
        // 1. Append 0x80 to the block and update the pos
        memset((void*)ctx->blk+ctx->pos, 0x80, 1);
        ctx->pos += 1;
        
        // 2. If pos > 57, compute block, and clear
        if (ctx->pos > 57) {
            __blk_htobe(ctx->blk);
            __sha512_compute(ctx->common.hash, ctx->blk);

            memset(ctx->blk, 0, 16 * sizeof(uint32_t));
            ctx->pos = 0;
        }

        // 3. Append bitlen at the last 64-bit position
        uint64_t bits = htobe64(ctx->tot * 8);
        memcpy(((void*)ctx->blk)+64-sizeof(uint64_t), &bits, sizeof(uint64_t));

        // 4. compute the last block
        __blk_htobe(ctx->blk);
        __sha512_compute(ctx->common.hash, ctx->blk);
 
        // 5. return success
        rv = RV_SUCCESS;
    }

    return rv;
}

void sha512_print(hash_ctx_t *ctx, const char *fname) {
}

void sha512_print_bsd(hash_ctx_t *ctx, const char *fname) {
}
