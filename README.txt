sha1extend

This program implements the Length Extension Attack on the SHA1
algorithm. It was written in order to aid in CTF competitions and to
understand the attack/hashing algorithms better. I only tested it on
linux but it is quite simple so i guess it could work elsewhere with
small modifications.

You may find an overview of the attack at the bottom of this readme,
though i recommend reading more detailed explanations somewhere else,
there is a plenty of articles online. Wikipedia has a good explanation:
https://en.wikipedia.org/wiki/Length_extension_attack

How to build

Use make to build and make clear to remove build files. The binary is
called sha1extend. No libraries are necessary outside of libc and maybe
some standard linux things.

Usage

    [msaw328@linux]$ ./sha1extend -h
    sha1extend - tool to perform the Length Extension Attack on SHA1
    Options:
            -h: print this usage and exit
            -s <signature>: original signature in hex
            -l <number>: length of the data which produced the original signature
            -a <string>: data to be appended

SHA1 implementation usage

I am not the author of the SHA1 implementation used in this tool.
Original author credited in the source file is Steve Reid
(steve@edmweb.com). More details can be found in the
sha1_implementation_usage.txt file.

License

All the code outside of the SHA1 implementation in sha1.c and sha1.h
files is licensed under LGPL, as described in the LICENSE file.

Overview of the Length Extension Attack

During finalization of the SHA1 algorithm, the input is padded to a
multiple of 512 bits (64 bytes) using a sequence of bytes. The sequence
is usually known as "padding" and it relies only on the length of the
input consumed prior to finalization. After finalization, the hash
digest is produced from internal state of the algorithm after the
padding has been appended. This is done in an invertible way, which
means that an attacker may recreate the padding which was appended to
the input during finalization, as well as the internal state of the
algorithm afterwards without knowing a single byte of the input. They
only need to know the length of the input and the resulting hash digest.
Once they know the internal state of the algorithm "paused" after the
original padding, they may append any data they need to the input and
calculate a new valid hash digest.

Basically, assume that there is a sequence of bytes known as
"secretdata". The attacker does not know the contents of the sequence,
but they know its length and the SHA1 hash of it. They wish to append
their own sequence of bytes called "attackerdata" to it. Using this
attack they are able to calculate a valid SHA1 hash of the sequence
"secretdata + padding + attackerdata".

Simple example

Example attack may be performed using nothing but "echo" and "sha1sum",
two commands available on many operating systems.

1.  Generate the SHA1 hash of original data, for instance the string
    "Hello" (-n prevents echo from appending a newline to the output):

    [msaw328@linux]$ echo -en "Hello" | sha1sum 
    f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0  -

2.  Assume we want to append the string "World!" to the original data
    and calculate the hash of that, without knowing the original
    contens, only length (5). The tool can be invoked in the following
    manner:

    [msaw328@linux]$ ./sha1extend -l 5 -s f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0 -a "World!"
    New digest: 341B56EF8CB07AA0622E2EBCA41FDE9AE7A17E83
    Full append: \x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x28World!

Since the padding bytes are mostly unprintable, they are instead printed
using the "\x" escape sequence. This result means that after appending
the "\x80\x00\x00...\x00\x28World!" sequence to the original data and
hashing the result, one would get a hash equal to
"341B56EF8CB07AA0622E2EBCA41FDE9AE7A17E83".

3.  Verify the result using echo again:

    [msaw328@linux]$ echo -en "Hello\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x28World!" | sha1sum 
    341b56ef8cb07aa0622e2ebca41fde9ae7a17e83  -

All the results are NOT machine dependend, which means that you should
get exactly the same results as shown above.
