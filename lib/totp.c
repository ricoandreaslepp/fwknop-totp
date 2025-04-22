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

/* TODO: considering passing TOTP code by reference here as well */

int
fko_totp_key_derivation(uint32_t totp_code, char **key, int *key_len)
{
    // convert to hex and write to char buffer
    unsigned char totp[DIGITS] = {0};
    for (size_t i = 1; i <= DIGITS; i++)
    {
        totp[DIGITS - i] = (char)('0' + (totp_code % 10));
        totp_code /= 10;
    }
    /* TODO: verify memory allocation */
    *key = malloc(SHA256_DIGEST_LEN + 1);

    // calculate and store hash
    sha256(*key, totp, DIGITS);

    // change key size to hash output length
    *key_len = SHA256_DIGEST_LEN;

    return 1;
}

int 
fko_totp_from_secret(uint32_t *totp_code, const char * const secret, uint64_t *timestamp, char *time_step)
{
    // HMAC-SHA1 result buffer
    uint8_t hmac_result[HMAC_LENGTH] = {0};

    // configure timestamp (T)
    uint64_t T = (uint64_t)floor((*timestamp - T0) / X) - *time_step;
    char time_buf[TIME_LEN] = {0};

    for (char i = 1; i <= TIME_LEN; i++)
    {
        time_buf[TIME_LEN - i] = (char)(((T >> 4) % 0x10) << 4 | (T % 0x10));
        T >>= 8;
    }

    if(hmac_sha1((const char *)time_buf, TIME_LEN, hmac_result, secret, SECRET_LEN) != FKO_SUCCESS)
        return 0;

    //// TODO: refactor
	*totp_code = dynamic_truncation(hmac_result) % (int)floor(pow(10.0, DIGITS)); 
    return 1;
}
