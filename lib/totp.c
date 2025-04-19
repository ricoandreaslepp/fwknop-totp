// libfko imports
#include "fko_common.h"
#include "fko.h"
#include "hmac.h"

// others
#include <math.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

#define SECRET_LEN 20
#define HMAC_LENGTH 20
#define TIME_LEN 8
#define DIGITS 6 // OTP digits
#define X 30 // default time step
#define T0 0 // default value

uint32_t dynamic_truncation(unsigned char* hmac_result)
{
    uint32_t bin_code, offset;

    /* RFC4226 p7-8 */  
    offset = hmac_result[HMAC_LENGTH - 1] & 0xf;

    bin_code = (hmac_result[offset] & 0x7f) << 24
    | (hmac_result[offset+1] & 0xff) << 16
    | (hmac_result[offset+2] & 0xff) << 8
    | (hmac_result[offset+3] & 0xff);

    return bin_code;
}

int totp()
{
    // store the final TOTP
    uint32_t totp;

    // key and counter
    uint8_t hmac_result[HMAC_LENGTH];

    //// TODO: secret generation
    // configure the secret (K)
    const char secret[] = "12345678901234567890";

    // configure time timestamp (T)
    uint64_t T = (time(NULL) - T0)/X;
    char time_buf[TIME_LEN];

    //// TODO: THIS SHOULD NOT BE STATIC
    int hex_len = 4;
    for (size_t i = 1; i <= hex_len; i++)
    {
        time_buf[TIME_LEN - i] = (char)(((T >> 4) % 0x10) << 4 | (T % 0x10));
        T >>= 8;
    }

    // clear the rest of the buffer
    for (size_t i = 0; i < TIME_LEN - 1 - hex_len;++i)
    {
        time_buf[i] = (char)0;
    }

    //// TODO: hmac_sha1 returns FKO_SUCCESS
    hmac_sha1((const char *)time_buf, TIME_LEN, hmac_result, secret, SECRET_LEN);

    //// TODO: refactor
	totp = dynamic_truncation(hmac_result) % (int)floor(pow(10.0, DIGITS)); 
    return (int)totp;
}