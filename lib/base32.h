#ifndef BASE32_H
#define BASE32_H 1

/* Prototypes
*/
int b32_encode(unsigned char *in, char *out, int in_len);
int b32_decode(const char *in, unsigned char *out);

#endif /* BASE32_H */

/***EOF***/