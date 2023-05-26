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

// hexconv.c - routines used to convert between binary buffers of bytes and hex strings

#include "hexconv.h"

#include <stddef.h>
#include <stdint.h>

#include <stdio.h>

// Nibble is in the lower 4 bits
char _nibble2char(uint8_t nibble) {
    nibble &= 0x0f;

    if(nibble < 10) return '0' + nibble;

    return 'A' + nibble - 10;
}

// Returns 0 for invalid chars because im too lazy to check errors
uint8_t _char2nibble(char c) {
    if('A' <= c && c <= 'F') return (uint8_t) c - (uint8_t) 'A' + 10;
    if('a' <= c && c <= 'f') return (uint8_t) c - (uint8_t) 'a' + 10;
    if('0' <= c && c <= '9') return (uint8_t) c - (uint8_t) '0';

    return 0;
}

void bytes2hex(uint8_t* in_bytes, char* out_str, size_t bytes_len) {
    for(size_t i = 0; i < bytes_len; i++) {
        out_str[2 * i] = _nibble2char(in_bytes[i] >> 4);
        out_str[2 * i + 1] = _nibble2char(in_bytes[i]);
    }

    out_str[bytes_len * 2] = '\0';
}

void hex2bytes(char* in_str, uint8_t* out_bytes, size_t bytes_len) {
    for(size_t i = 0; i < bytes_len; i++) {
        out_bytes[i] = (_char2nibble(in_str[2 * i]) << 4) + _char2nibble(in_str[2 * i + 1]);
    }
}
