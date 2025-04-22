// libfko imports
#include "fko.h"
#include "hmac.h" // already includes "digest.h"

// others
#include <math.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define SECRET_LEN 20
#define HMAC_LENGTH 20
#define TIME_LEN 8
#define DIGITS 6 // OTP digits
#define X 30 // default time step
#define T0 0 // default value
