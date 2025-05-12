#include "base32.h"

static unsigned char map3[] = {
    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0xff, 0xff, // starts from 50
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 
    0x19
};

int
b32_encode(unsigned char *in, char *out, int in_len)
{
    static const char b32[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    unsigned i_bits = 0;
    int i_shift = 0;
    int bytes_remaining = in_len;

    char *dst = out;

    if (in_len > 0) {
        while (bytes_remaining) {
            i_bits = (i_bits << 8) + *in++;
            bytes_remaining--;
            i_shift += 8;

            /* concat 5 8-bit input groups */
            do {
                *dst++ = b32[(i_bits << 5 >> i_shift) & 0x1f];
                i_shift -= 5;
            } while (i_shift > 5 || (bytes_remaining == 0 && i_shift > 0));
        }
    }

    *dst = '\0';

    return(dst - out);
}

int
b32_decode(const char *in, unsigned char *out)
{
    int i, bits;
    unsigned long v;
    unsigned char *dst = out;

    v = 0, bits = 0;
    for (i = 0; in[i] && in[i] != '='; i++) {
        unsigned int index= in[i]-50;

        if (index>=(sizeof(map3)/sizeof(map3[0])) || map3[index] == 0xff)
            return(-1);

        v = (v << 5) + map3[index];
        bits += 5;

        /* a bit of a hacky way, but it works */
        while (bits >= 8) {
            *dst++ = (v >> (bits - 8)) & 0xff; 
            bits -= 8;
        }
    }

    *dst = '\0';

    return(dst - out);
}
