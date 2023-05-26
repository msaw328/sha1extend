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

// hexconv.h - routines used to convert between binary buffers of bytes and hex strings

#ifndef _HEXCONV_H_
#define _HEXCONV_H_

// Convert from an array of uint8_t to hex string and vice-versa
// All hex uses uppercase letters because that's old-school and im
// too lazy to allow the caller to switch to lowercase, too many if-elses

#include <stddef.h>
#include <stdint.h>

// In case of both functions, bytes_len means the size of the uint8_t buffer
// In both cases, the size of allocated space for the string should be at least 2x bytes_len + 1 byte for a null character
void bytes2hex(uint8_t* in_bytes, char* out_str, size_t bytes_len);
void hex2bytes(char* in_str, uint8_t* out_bytes, size_t bytes_len);

#endif
