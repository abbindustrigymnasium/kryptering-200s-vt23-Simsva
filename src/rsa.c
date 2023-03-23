#include <algorithms.h>

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#define RABIN_MILLER_ITER 5

static uintmax_t powmod(uintmax_t b, uintmax_t e, uintmax_t m) {
    if(m == 1) return 0;
    uintmax_t c = 1;

    for(uintmax_t i = 0; i < e; i++)
        c = (c*b) % m;
    return c;
}

/* extended Euclidian algorithm */
static intmax_t modinv(intmax_t a, intmax_t m) {
    intmax_t m0 = m, y = 0, x = 1;

    if(m == 1) return 0;

    while(a > 1) {
        intmax_t q = a/m, t = m;

        m = a % m; a = t;
        t = y;

        y = x - q*y;
        x = t;
    }

    return x + m0*(x < 0);
}

static int rabin_miller(uint32_t candidate) {
    uint32_t even, max_div_2;

    even = candidate-1;
    max_div_2 = 0;
    while(even % 2 == 0) even >>= 1, max_div_2++;

    for(unsigned i = 0; i < RABIN_MILLER_ITER; i++) {
        uint32_t round_tester = rand()*(candidate - 2) + 2;

        if(powmod(round_tester, even, candidate) == 1)
            continue;
        for(unsigned j = 0; j < max_div_2; j++)
            if(powmod(round_tester, (1<<j)*even, candidate) == candidate - 1)
                continue;

        return 0;
    }

    return 1;
}

uint16_t primes[100] = {
    2,   3,   5,   7,  11,  13,  17,  19,  23,  29,
   31,  37,  41,  43,  47,  53,  59,  61,  67,  71,
   73,  79,  83,  89,  97, 101, 103, 107, 109, 113,
  127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
  179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
  233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
  283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
  353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
  419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
  467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
};
static uintmax_t generate_prime(uint8_t bit) {
    uintmax_t candidate;

redo:
    /* generate an odd number with bit-length "bit" */
    candidate = (1<<(bit-1)) | (1<<0) | ((rand() % (1<<(bit-2)))<<1);

    for(uint8_t i = 0; i < sizeof(primes)/sizeof(primes[0]); i++)
        if(candidate % primes[i] == 0)
            goto redo;

    if(!rabin_miller(candidate)) goto redo;

    return candidate;
}

void algo_fake_rsa(void) {
    uint16_t p, q;
    uint32_t e, d, n, totient;
    char buf[256];

    do
        p = generate_prime(16), q = generate_prime(16);
    while(p == q);
    n = p*q; totient = (p-1)*(q-1);
    e = 65537;
    d = modinv(e, totient);

    /* this is horribly space-inefficient especially for large values of n
     * (which is at most 4 bytes here) */
    printf("plaintext: ");
    fgets(buf, sizeof buf, stdin);
    printf("ciphertext (hex): ");
    for(char *c = buf; *c; c++)
        printf("%08"PRIX32, (uint32_t)powmod(*c, e, n));
    printf("\n(d, n) = (%"PRIu32", %"PRIu32")\n", d, n);
}

void algo_rsa(void) {
    uint16_t p, q;
    uint32_t e, d, n, totient, m;

    do
        p = generate_prime(16), q = generate_prime(16);
    while(p == q);
    n = p*q; totient = (p-1)*(q-1);
    e = 65537;
    d = modinv(e, totient);

    printf("m: ");
    scanf("%"SCNu32, &m);
    printf("c: %"PRIu32"\n", (uint32_t)powmod(m, e, n));
    printf("\n(d, n) = (%"PRIu32", %"PRIu32")\n", d, n);
}
