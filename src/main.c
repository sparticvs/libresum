/* main.c - LibreSUM's main file
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <strings.h>

#define VER_MAJ     1
#define VER_MIN     0

// Verify's Verbosity Levels
#define LVL_DEFAULT 0
#define LVL_QUIET   1
#define LVL_STATUS  2

// Algorithm
#define ALGO_SHA1_STR       "sha1"
#define ALGO_SHA224_STR     "sha224"
#define ALGO_SHA256_STR     "sha256"
#define ALGO_SHA384_STR     "sha384"
#define ALGO_SHA512_STR     "sha512"
#define ALGO_SHA512_224_STR "sha512/224"
#define ALGO_SHA512_256_STR "sha512/256"
#define ALGO_SHA3_224_STR   "sha3-224"
#define ALGO_SHA3_256_STR   "sha3-256"
#define ALGO_SHA3_384_STR   "sha3-384"
#define ALGO_SHA3_512_STR   "sha3-512"

// Options Structure
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

static libresum_opts_t opts = {
    .algo = NULL,
    .binary = 0,
    .check = 0,
    .tag = 0,
    .text = 0,
    .level = LVL_DEFAULT,
    .warn = 0,
    .strict = 0,
};

static struct option long_opts[] = {
    {"algo", required_argument, &opts.algo, 'a'},
    {"binary", no_argument, &opts.binary, 1},
    {"check", no_argument, &opts.check, 1},
    {"tag", no_argument, &opts.tag, 1},
    {"text", no_argument, &opts.text, 1},
    {"quiet", no_argument, &opts.level, LVL_QUIET},
    {"status", no_argument, &opts.level, LVL_STATUS},
    {"warn", no_argument, &opts.warn, 1},
    {"strict", no_argument, &opts.strict, 1},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {NULL, NULL, NULL, NULL}
};

typedef struct {
    uint8_t *hash;
    uint32_t len;
    int ret;
} result_t;

// TODO refactor main to do options parsing in its own function
// TODO add algorithm selection with the options
// TODO implement hashsum checking
// TODO integrate the sha256sum code into this
// TODO move the file handling code from sha256 to here

void print_usage(const char *called_as) {
    printf("usage: %s [OPTION]... [FILE]...\n", called_as);
    printf("\n");
    printf("Print or check checksums based on the defined algorithm.\n");
    printf("With no FILE, or when FILE is -, read standard input.\n");
    printf("\n");
    printf("-a, --algo <algo>\talgorithm to use (sha256)\n");
    printf("-b, --binary\t\tread in binary mode\n");
    printf("-c, --check\t\tread sums from the FILEs and check them\n");
    printf("    --tag\t\tcreate a BSD-style checksum\n");
    printf("-t, --text\t\tread in text mode (default)\n");
    printf("\n");
    printf("The following three options are useful only when verifying checksums:\n");
    printf("    --quiet\t\tdon't print OK for each successfully verified file\n");
    printf("    --status\t\tdon't output anything, status code shows success\n");
    printf("-w, --warn\t\twarn about improperly formatted checksum lines\n");
    printf("\n");
    printf("    --strict\t\twith --check, exit non-zero for any invalid input\n");
    printf("    --help\t\tdisplay this help and exit\n");
    printf("    --version\toutput version information and exit\n");
}

void print_version() {
    printf("Copyright (c) 2016 - Charles `sparticvs` Timko\n");
    printf("libresum v%d.%d\n", VER_MAJ, VER_MIN);
}

int execute_algo(char *algo, FILE fp, result_t *result) {
    
    // TODO Match algo called with native function
    // TODO Call the algo specified
    // TODO Return the status from the function
}

int main(int argc, char **argv) {

    int c = 0;
    int opt_index = 0;
    do {
        c = getopt_long(argc, argv, "a:bctw", long_opts, &opt_index);
        switch(c) {
            case 0:
                // Stored...
                break;
            case '?':
                // Returned on an unknown character
            case 'h':
                print_usage(argv[0]);
                break;
            case 'v':
                print_version();
                break;
            case 'b':
                opts.binary = 1;
                break;
            case 'c':
                opts.check = 1;
                break;
            case 't':
                opts.tag = 1;
                break;
            case 'w':
                opts.warn = 1;
                break;
            case 'a':
                opts.algo = optarg;
                break;
            default:
                // Punt. Most likely -1
                break;
        }
    } while (-1 != c);

    if(opts.check) {
        // TODO Build a check table
        // TODO Calculate the sum of each file that is inculded in the file
        // TODO Compare with the check table
        // TODO Output the result depending on the flags that were set
    } else {
        // TODO Calculate the sum for each file that was referenced
        // TODO Print the result in the proper output
    }

    return 0;
}
