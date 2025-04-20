#include "totp.h"

uint32_t 
dynamic_truncation(unsigned char* hmac_result)
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

int 
fko_totp(uint32_t *totp_code)
{
    // key and counter
    uint8_t hmac_result[HMAC_LENGTH];

    //// TODO: secret generation
    // configure the secret (K)
    const char secret[] = "12345678901234567890";

    // configure time timestamp (T)
    uint64_t T = (time(NULL) - T0)/X;
    char time_buf[TIME_LEN] = {0};

    //// TODO: THIS SHOULD NOT BE STATIC
    // int hex_len = 4;
    // for (size_t i = 1; i <= hex_len; i++)
    // {
    //     time_buf[TIME_LEN - i] = (char)(((T >> 4) % 0x10) << 4 | (T % 0x10));
    //     T >>= 8;
    // }

    // assign the hex values
    time_buf[TIME_LEN - 1] = (char)0x1; // test vector 1 from RFC6238

    if (hmac_sha1((const char *)time_buf, TIME_LEN, hmac_result, secret, SECRET_LEN) != FKO_SUCCESS)
    {
        return 0;
    }

    //// TODO: refactor
	*totp_code = dynamic_truncation(hmac_result) % (int)floor(pow(10.0, DIGITS)); 
    return 1;
}