// sha1extend - A tool to perform the Length Extension Attack on SHA1
// Copyright (C) 2023  Maciej Sawka (msaw328) <maciejsawka@gmail.com, msaw328@kretes.xyz>
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA

// main.c - main() function, arg parsing and the bulk of programs functionality

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <endian.h>

#include "hexconv.h"
#include "sha1.h"

// Data supplied by the user below
uint8_t original_hash[20] = { 0 }; // -s
int hash_supplied = 0;

char* append = NULL; // -a

long original_length = 0; // -l
int length_supplied = 0;

// This initializes the SHA1_CTX structure to the intermediate state after consuming original data
void init_SHA1_ctx_intermediate_state(SHA1_CTX* ctx, uint8_t* hash, uint32_t data_len_so_far) {
    // Code pasted from implementation to encode string length as those weird counts
    uint32_t j = ctx->count[0];
    if ((ctx->count[0] += data_len_so_far << 3) < j)
        ctx->count[1]++;
    ctx->count[1] += (data_len_so_far >> 29);

    // Hash is big endian
    for(int i = 0; i < 5; i++) {
        ctx->state[i] = 0;
        for(int j = 0; j < 4; j++) {
            ctx->state[i] += hash[4 * i + j] << ((3 - j) * 8);
        }
    }
}

void print_usage_and_exit() {
    puts("sha1extend - tool to perform the Length Extension Attack on SHA1");
    puts("Options:");
    puts("\t-h: print this usage and exit");
    puts("\t-s <signature>: original signature in hex");
    puts("\t-l <number>: length of the data which produced the original signature");
    puts("\t-a <string>: data to be appended");
    exit(0);
}

// Checks if a string contains a valid SHA1 hash
int is_valid_hash(char* str) {
    size_t str_len = (size_t) ((uint8_t*) memchr(str, '\0', 41) - (uint8_t*) str);
    if(str_len != 40) return 0;

    for(size_t i = 0; i < str_len; i++) {
        char c = str[i];
        if(('A' <= c && c <= 'F') || ('a' <= c && c <= 'f') || ('0' <= c && c <= '9')) continue;

        return 0;
    }

    return 1;
}

// Parses and validates arguments and stores them in gloal variables defined at the very top of this file
void parse_args(int argc, char** argv) {
    int c = 0;
    while((c = getopt(argc, argv, "hs:l:a:")) != -1) {
        switch(c) {
            case 'h': {
                print_usage_and_exit();
            }

            case 's': {
                if(!is_valid_hash(optarg)) {
                    puts("Invalid signature");
                    print_usage_and_exit();
                }

                hex2bytes(optarg, original_hash, 20);
                hash_supplied = 1;
                break;
            }
            
            case 'l': {
                char* endptr = NULL;
                long length = strtol(optarg, &endptr, 0);
                if(endptr == optarg || *endptr != '\x0') {
                    puts("Invalid length");
                    print_usage_and_exit();
                }

                original_length = (uint32_t) length;
                length_supplied = 1;
                break;
            }

            case 'a': {
                append = optarg;
                break;
            }

            case '?': {
                if (optopt == 'c' || optopt == 'a' || optopt == 'l') {
                    printf("Option -%c requires an argument.\n", optopt);
                    print_usage_and_exit();
                }
            }
        }
    }

    if(hash_supplied == 0 || length_supplied == 0 || append == NULL) {
        puts("Missing arguments");
        print_usage_and_exit();
    }
}

int main(int argc, char** argv) {
    parse_args(argc, argv);

    SHA1_CTX ctx = { 0 };

    size_t padding_length = 64 - (original_length % 64);
    if(padding_length < 9) {
        padding_length += 64;
    }

    // Initialize SHA1_CTX to the intermediate state that we know:
    //  - length of the data consumed is the length of the data + the padding calculated above
    //  - the state afterwards is the original hash
    init_SHA1_ctx_intermediate_state(&ctx, original_hash, original_length + padding_length);

    // Update the state with the data we want to append
    SHA1Update(&ctx, (const unsigned char*) append, strlen(append));

    // Finalize, apply padding and produce a digest
    uint8_t digest[20] = { 0 };
    SHA1Final(digest, &ctx);

    char digest_hex[41] = { 0 };
    bytes2hex(digest, digest_hex, 20);

    printf("New digest: %s\n", digest_hex);

    // Padding is made of unprintable bytes so we print those as \x escape sequences
    printf("Full append: \\x80");
    for(int i = 0; i < padding_length - 9; i++) {
        printf("\\x00");
    }

    // Afterwards length is printed, also using \x sequences in big endian order
    uint64_t biglength = (uint64_t) original_length;
    biglength = biglength << 3; // In bits

    for(int i = 0; i < 8; i++) {
        uint8_t byte = (uint8_t) (biglength >> ((7 - i) * 8)) & 0xff;
        printf("\\x%02X", byte);
    }

    // The append part is most likely printable so we can just print it directly
    puts(append);
}
