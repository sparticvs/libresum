/* sha256.c - Implementation of the SHA-256 algorithm
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

    usage: sha256sum [OPTION]... [FILE]...

    Print or check SHA256 (256-bit) checksums.
    With no FILE, or when FILE is -, read standard input.

    -b, --binary         read in binary mode
    -c, --check          read SHA256 sums from the FILEs and check them
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
#include "sha256.h"

#define ARRAY_SZ    1024*32

#define CH(x,y,z)   ((x&y)^(~x&z))
#define MAJ(x,y,z)  ((x&y)^(x&z)^(y&z))
#define ROTR(n,x)   ((x>>n)|(x<<(32-n)))
#define CS0(x)      (ROTR(2,x) ^ ROTR(13,x) ^ ROTR(22,x))
#define CS1(x)      (ROTR(6,x) ^ ROTR(11,x) ^ ROTR(25,x))
#define SS0(x)      (ROTR(7,x) ^ ROTR(18,x) ^ (x >> 3))
#define SS1(x)      (ROTR(17,x) ^ ROTR(19,x) ^ (x >> 10))

// TODO Move byte order functions to a compat.h file
// TODO Implement verbosity level when checking
// TODO Implement NESSIE vectors on a test switch
// TODO Flow control implementations

/*
 * Note
 *
 * The intent is to mimic as much as possible the Perl script and it's output.
 * However, we will also support other output types, but we may require a
 * flag to do so.
 */

// This is logical, as you can fscanf and have all the data you need
#define DEFAULT_OUTPUT  "%08x%08x%08x%08x%08x%08x%08x%08x %c%s\n"
// The %c is to output a `*' if the hash was done in binary mode
// but on *NIX systems, this doesn't really matter as binary mode is
// the same as text mode. We do, however, want to implement this
// correctly... There are other character outputs as well, need to
// investigate what those are and what we need to do for them.
#define BSD_OUTPUT "SHA256 (%s) = %08x%08x%08x%08x%08x%08x%08x%08x\n"

static const uint32_t H256[] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
};

static const uint32_t K256[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

hash_ctx_t* sha256_ctx_new(hash_algo_t *algo) {
    sha256_ctx_t *ctx = NULL;

    ctx = malloc(sizeof(sha256_ctx_t));
    if(NULL == ctx) {
        return NULL;
    }

    ctx->common.algo = algo;

    ctx->common.hash = malloc(SHA256_HASH_WORD_LEN * SHA256_WORD_SZ);
    if(NULL == ctx->common.hash) {
        free(ctx);
        return NULL;
    }

    ctx->common.len = SHA256_HASH_WORD_LEN;

    return &(ctx->common);
}

void sha256_ctx_free(hash_ctx_t *ctx) {
    sha256_ctx_t *sha_ctx = (sha256_ctx_t*)ctx;
    if(NULL != sha_ctx) {
        free(sha_ctx->common.hash);
        free(sha_ctx);
    }
}

/**
 * SHA2-256 Message Schedule
 *
 * This will prepare the message schedule as per the FIPS standard
 *
 * @param sched     64-byte allocate for working in place on the schedule
 * @param msg       16-byte long message used to build the message schedule
 *
 * @return Returns an RV_ value
 */
rv_t __sha256_msg_sched(uint32_t *sched, const uint32_t * const msg) {
    rv_t retval = RV_UNKNOWN;

    if (NULL == sched || NULL == msg) {
        retval = RV_INVALARG;
    }

    if (RV_UNKNOWN == retval) {
        uint32_t j = 0;
        for(j = 0; j < 16; j++) {
            sched[j] = msg[j];
        }

        for(j = 16; j < 64; j += 2) {
            sched[j] = SS1(sched[j-2]) + sched[j-7] + SS0(sched[j-15]) + sched[j-16];
            sched[j+1] = SS1(sched[j-1]) + sched[j-6] + SS0(sched[j-14]) + sched[j-15];
        }

        retval = RV_SUCCESS;
    }

    return retval;
}

/**
 * SHA2-256 Computation
 *
 * Computes the SHA-256 hash on block boundary and is supplied the H(i-1)
 * This isn't intended to be exposed and could be shared between algos.
 *
 * @param hash      256-bit hash, updated in place
 * @param msg       256-bytes of the message
 *
 * @return Returns an RV_ value
 */
rv_t __sha256_compute(uint32_t *hash, const uint32_t * const msg) {
    rv_t retval = RV_UNKNOWN;
    if (NULL == hash || NULL == msg) {
        retval = RV_INVALARG;
    }
    uint32_t a, b, c, d, e, f, g, h, T1, T2, j;
    uint32_t W[64] = {0};

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
    if (RV_SUCCESS != __sha256_msg_sched(W, msg)) {
        retval = RV_NESTEDERR;
    }

    if (RV_UNKNOWN == retval) {
        for(j = 0; j < 64; j++) {
            T1 = h + CS1(e) + CH(e, f, g) + K256[j] + W[j];
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

/*
 * Here's an idea...
 *
 * Add a -j for the number of threads to use
 * Add a -o to enforce ordering of output (only useful with -j)
 *
 * When hashing a long list of files or validating files, we could speed
 * up the process with more threads. It is possible that they return out of
 * order, so a -o will enforce the order they where added as the order they are
 * output (would be useful for scripts that want to let some items be
 * permissiable if they fail validation)
 *
 * FILE1 FILE2 FILE3
 *
 * -j3 will use 3 threads total to calculate the sha256sums
 * -o addded will enforce the output printing to be:
 *      <hash1>  FILE1
 *      <hash2>  FILE2
 *      <hash3>  FILE3
 *
 * whereas without it, it could be
 *      <hash1>  FILE1
 *      <hash3>  FILE3
 *      <hash2>  FILE2
 *
 * If you are validating, then threads are used differently
 *
 * Say you have 3 checksum files, 1-3 as below.
 *
 * CHKSUM1 CHKSUM2 CHKSUM3
 *
 * -j3 will actually use 4 threads
 *
 * 1 thread will be allocated to parsing the checksum files
 * 3 threads will be used for validation
 *
 * This is really useful when you need to verify a large list of files
 *
 * -o will enforce output like so
 *
 * <CHKSUM1:FILE1>: OK
 * <CHKSUM1:FILE2>: OK
 * <CHKSUM2:FILE1>: OK
 * <CHSKUM3:FILE1>: FAILED
 *
 * without -o, the output could look something like this
 *
 * <CHKSUM1:FILE1>: OK
 * <CHKSUM2:FILE1>: FAILED
 * <CHKSUM3:FILE1>: OK
 * <CHKSUM1:FILE2>: OK
 *
 * Likely, the largest files will finish last, but this isn't always the case.
 */

//void unit_tests() {
//    printf("========================================\n");
//    printf(" Rotate Right Validation Test\n");
//    printf("========================================\n");
//    // Tests for now...
//    uint8_t i = 0, j = 0, valid = 1;
//
//    uint32_t rr1 = 0x12345678;
//
//    for(i = 0; i < 4; i++) {
//        printf("Rotate Right: %08x -> %08x\n", rr1, ROTR(i*8, rr1));
//    }
//
//    printf("========================================\n");
//    printf(" NESSIE Test Vectors (Set 1, Vector 0-7)\n");
//    printf("========================================\n");
//    for(i = 0; i < NESSIE_TV_MAX; i++) {
//        uint32_t *h = sha256sum(NESSIE_TV[i].tv, NESSIE_TV[i].len);
//        for(j = 0; j < 8; j++) {
//            valid &= (h[j] == NESSIE_TV[i].hash[j]);
//        }
//        printf("Test #%d: ", i);
//        if(valid) {
//            puts("PASSED");
//        } else {
//            puts("FAILED");
//        }
//        free(h);
//    }
//}

/**
 * SHA256 Initialize
 *
 * @param ctx       Pointer to sha-256 context to initialize
 *
 * @return Returns an RV_ value.
 */
rv_t sha256_initialize(hash_ctx_t *hash_ctx) {
    rv_t rv = RV_UNKNOWN;

    if (NULL == hash_ctx) {
        rv = RV_INVALARG;
    } else {
        sha256_ctx_t *ctx = (sha256_ctx_t*)hash_ctx;

        // We are in a stable state, initialize
        memcpy(ctx->common.hash, H256, SHA256_HASH_WORD_LEN * SHA256_WORD_SZ);

        // Clear out the blk
        memset(ctx->blk, 0, SHA256_BLOCK_WORD_LEN * SHA256_WORD_SZ);

        ctx->pos = 0;
        ctx->tot = 0;

        // Ok, we got here, set the RV
        rv = RV_SUCCESS;
    }

    return rv;
}

static inline void __blk_htobe(uint32_t *data) {
    // We assume block size
    uint8_t i;
    for (i = 0; i < SHA256_BLOCK_WORD_LEN; i++) {
        data[i] = htobe32(data[i]);
    }
}


/**
 * SHA256 Update
 *
 * @param ctx       Pointer to sha-256 context to operate on
 * @param data      Pointer to data blob to bring into the hash
 * @param len       Length of the data that is being updated in bytes
 *
 * @return Returns an RV_ value
 */
rv_t sha256_update(hash_ctx_t *hash_ctx, uint8_t *data, uint64_t len) {
    rv_t rv = RV_UNKNOWN;

    if (NULL == hash_ctx || NULL == data) {
        rv = RV_INVALARG;
    } else {
        sha256_ctx_t *ctx = (sha256_ctx_t*)hash_ctx;
        // 1. If ctx->pos > 0, fill blk up and process, memmove data and change
        // length
        if (ctx->pos > 0) {
            uint8_t avail = SHA256_BLOCK_LEN - ctx->pos;
            if (len < avail) {
                avail = len;
            }
            memcpy((void*)ctx->blk+ctx->pos, (void*)data, avail);
            ctx->pos += avail;

            memmove((void*)data+avail, (void*)data, avail);
            len -= avail;

            if (ctx->pos == SHA256_BLOCK_LEN) {
                __blk_htobe(ctx->blk);
                __sha256_compute(ctx->common.hash, ctx->blk);
                ctx->tot += avail;

                memset(ctx->blk, 0, SHA256_BLOCK_WORD_LEN * SHA256_WORD_SZ);
                ctx->pos = 0;
            }
        }

        // 2. If len % 64 != 0, move extra into ctx->blk
        if (len > 0 && len % SHA256_BLOCK_LEN != 0) {
            uint8_t rem = len % SHA256_BLOCK_LEN;
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
        for (cnt = 0; cnt < len / SHA256_BLOCK_LEN; cnt++) {
            __blk_htobe((void*)data+(SHA256_BLOCK_LEN*cnt));
            __sha256_compute(ctx->common.hash, (void*)data+(SHA256_BLOCK_LEN*cnt));
            ctx->tot += SHA256_BLOCK_LEN;
        }

        // 4. Set return value
        rv = RV_SUCCESS;
    }

    return rv;
}

/**
 * SHA-256 Finalize
 *
 * Finish the SHA-256 computation. This pads the blocks correctly and does the
 * final update to the hash.
 *
 * @param ctx       Pointer to the sha-256 context to finalize
 *
 * @return Returns an RV_ value
 */
rv_t sha256_finalize(hash_ctx_t *hash_ctx) {
    rv_t rv = RV_UNKNOWN;

    if (NULL == hash_ctx) {
        rv = RV_INVALARG;
    } else {
        sha256_ctx_t *ctx = (sha256_ctx_t*)hash_ctx;
        // 1. Append 0x80 to the block and update the pos
        memset((void*)ctx->blk+ctx->pos, 0x80, 1);
        ctx->pos += 1;

        // 2. If pos > 57, compute block, and clear
        if (ctx->pos > SHA256_LAST_BLOCK_MAX) {
            __blk_htobe(ctx->blk);
            __sha256_compute(ctx->common.hash, ctx->blk);

            memset(ctx->blk, 0, SHA256_BLOCK_WORD_LEN * SHA256_WORD_SZ);
            ctx->pos = 0;
        }

        // 3. Append bitlen at the last 64-bit position
        uint64_t bits = htobe64(ctx->tot * 8); // Converting to bits inline
        memcpy(((void*)ctx->blk)+SHA256_BLOCK_LEN-sizeof(uint64_t), &bits, sizeof(uint64_t));

        // 4. compute the last block
        __blk_htobe(ctx->blk);
        __sha256_compute(ctx->common.hash, ctx->blk);

        // 5. return success
        rv = RV_SUCCESS;
    }

    return rv;
}

void sha256_print(hash_ctx_t *ctx, const char *fname) {
    size_t i;
    for(i = 0; i < ctx->len; i++) {
        printf("%08x", ((uint32_t*)ctx->hash)[i]);
    }
    printf(" %c%s\n", ' ', fname);
}

void sha256_print_bsd(hash_ctx_t *ctx, const char *fname) {
    size_t i;
    printf("%s (%s) = ", ctx->algo->name, fname);
    for(i = 0; i < ctx->len; i++) {
        printf("%08x", ((uint32_t*)ctx->hash)[i]);
    }
    printf("\n");
}

rv_t sha256_parse(const char *str, checkentry_t *entry) {
    size_t i = 0;
    if(NULL == str || NULL == entry) {
        return RV_INVALARG;
    }

    // Look up the algorithm
    entry->valid_hash = malloc(SHA256_HASH_WORD_LEN * SHA256_WORD_SZ);
    if(NULL == entry->valid_hash) {
        return RV_NESTEDERR;
    }
    entry->len = SHA256_HASH_WORD_LEN;

    for(i = 0; i < entry->len; i++) {
        sscanf(str, "%8x", ((uint32_t*)entry->valid_hash) + i);
    }

    return RV_SUCCESS;
}

bool sha256_compare(hash_ctx_t *ctx, checkentry_t *entry) {
    size_t i;
    if(NULL == ctx || NULL == entry) {
        return false;
    }

    if(SHA256_HASH_WORD_LEN != entry->len) {
        return false;
    }

    if(memcmp(ctx->hash, entry->valid_hash, SHA256_WORD_SZ * SHA256_HASH_WORD_LEN)) {
        return false;
    }

    return true;
}

#define NESSIE_TV_MAX 8
const testvector_t NESSIE_SHA256_TV[] = {
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
