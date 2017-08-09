/* base_types.h - LibreSUM's Base Types Header
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

#ifndef __BASE_TYPES_H__
#define __BASE_TYPES_H__

#include <stdint.h>
#include <stdbool.h>

typedef uint8_t rv_t;

#define RV_SUCCESS      0
#define RV_INVALARG     1
#define RV_NESTEDERR    2
/**
 * @note
 * RV_UNKNOWN never is returned in any legitimate execution. It is only
 * returned if something erraneous happens on the proccessor. If this is being
 * used in a sensitive context, then you will want to assert that you never
 * receive this.
 */
#define RV_UNKNOWN      255

/**
 * Options from command line
 */
typedef struct {
    char * algo;    ///< Pointer to Algorithm String
    uint8_t binary; ///< Binary Mode Flag
    uint8_t check;  ///< Check Mode Flag
    uint8_t tag;    ///< BSD Format Flag
    uint8_t text;   ///< Text Mode Flag
    uint8_t level;  ///< Verbosity Level Flag
    uint8_t warn;   ///< Warn Only Flag
    uint8_t strict; ///< Strict Checking Flag
} libresum_opts_t;

typedef struct node node_t;
struct node {
    node_t *next;
};

typedef struct hash_algo hash_algo_t;

/**
 * @note
 * These are required parameters that will need to be populated by the
 * conclusion of your calculations.
 */
typedef struct {
    hash_algo_t *algo;
    void *hash;
    size_t len;
} hash_ctx_t;

/**
 * Structure used by Checksum Validation
 */
typedef struct checkentry checkentry_t;
struct checkentry {
    checkentry_t *next;     ///< Next Node in the List
    hash_algo_t *algo;       ///< Algorithm Name
    void *valid_hash;       ///< Valid Hash to check against
    size_t len;             ///< Length of the hash in bytes
    char file[FILENAME_MAX];///< Name of file to validate
};

struct hash_algo {
    const char *name;
    const char *bsd_tag;
    const char *binary_name;
    rv_t (*init)(hash_ctx_t *);
    rv_t (*update)(hash_ctx_t *, uint8_t *, uint64_t);
    rv_t (*final)(hash_ctx_t *);
    hash_ctx_t *(*new)(hash_algo_t *);
    void (*free)(hash_ctx_t *);
    void (*print)(hash_ctx_t *, const char *);
    void (*print_bsd)(hash_ctx_t *, const char *);
    rv_t (*parse)(const char *, checkentry_t *);
    bool (*compare)(hash_ctx_t *, checkentry_t *);
};


#endif //_BASE_TYPES_H__
