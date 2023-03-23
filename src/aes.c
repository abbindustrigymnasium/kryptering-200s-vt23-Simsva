#include <algorithms.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define AES_KEYLEN     16            /* key size in bytes */
#define AES_KEYEXPSIZE (16*11)       /* expanded key size */
#define AES_BLOCKLEN   16            /* block size in bytes */

#define AES_COLUMNS    4             /* number of columns in state matrix */
#define AES_KEY_WORD   4             /* number of 32-bit words in key */
#define AES_ROUNDS     10            /* number of cipher rounds */

struct ctx {
    uint8_t round_key[AES_KEYEXPSIZE];
    uint8_t iv[AES_BLOCKLEN];
};

/* state matrix */
typedef uint8_t state_t[4][4];

/* forward declarations */
void ctx_init(struct ctx *ctx, const uint8_t *key, const uint8_t *iv);

/* buf is used as the output so its size must be a multiple of AES_BLOCKLEN */
void cbc_encrypt_buf(struct ctx *ctx, uint8_t *buf, size_t sz);
void cbc_decrypt_buf(struct ctx *ctx, uint8_t *buf, size_t sz);

size_t pad_pkcs7(uint8_t *buf, size_t blocksz, size_t sz);
size_t unpad_pkcs7(uint8_t *buf, size_t sz);

static void xor_block(uint8_t *a, const uint8_t *b);
static void add_round_key(state_t *state, const uint8_t *round_key, uint8_t round);
static void sub_bytes(state_t *state);
static void sub_bytes_inv(state_t *state);
static void shift_rows(state_t *state);
static void shift_rows_inv(state_t *state);
static uint8_t xtime(uint8_t x);
static uint8_t gmul(uint8_t a, uint8_t b);
static void mix_columns(state_t *state);
static void mix_columns_inv(state_t *state);
static void key_expansion(uint8_t *round_key, const uint8_t *key);
static void cipher(state_t *state, uint8_t *round_key);
static void cipher_inv(state_t *state, uint8_t *round_key);
static void keygen(uint8_t *key, size_t sz);
static void print_hex(uint8_t *buf, size_t sz);

static const uint8_t sbox[0x100] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t rsbox[0x100] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

static const uint8_t rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

static void xor_block(uint8_t *a, const uint8_t *b) {
    for(uint8_t i = 0; i < AES_BLOCKLEN; i++)
        a[i] ^= b[i];
}

/* XOR state with round key
 * is its own inverse */
static void add_round_key(state_t *state, const uint8_t *round_key, uint8_t round) {
    uint8_t i, j;
    for(i = 0; i < 4; i++)
        for(j = 0; j < 4; j++)
            (*state)[i][j] ^= round_key[round*16 + i*4 + j];
}

/* substitute all bytes in state */
static void sub_bytes(state_t *state) {
    uint8_t i, j;
    for(i = 0; i < 4; i++)
        for(j = 0; j < 4; j++)
            (*state)[i][j] = sbox[(*state)[i][j]];
}

static void sub_bytes_inv(state_t *state) {
    uint8_t i, j;
    for(i = 0; i < 4; i++)
        for(j = 0; j < 4; j++)
            (*state)[i][j] = rsbox[(*state)[i][j]];
}

/* shift/rotate rows in state */
static void shift_rows(state_t *state) {
    uint8_t temp;

    temp           = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

static void shift_rows_inv(state_t *state) {
    uint8_t temp;

    temp           = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;

    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;
}

static uint8_t xtime(uint8_t x) {
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

/* multiply in GF(2**8) */
static uint8_t gmul(uint8_t a, uint8_t b) {
    return (((b & 1) * a) ^
         ((b>>1 & 1) * xtime(a)) ^
         ((b>>2 & 1) * xtime(xtime(a))) ^
         ((b>>3 & 1) * xtime(xtime(xtime(a)))) ^
         ((b>>4 & 1) * xtime(xtime(xtime(xtime(a))))));
}

/* I have literally no idea why this works but it apparently does matrix
 * multiplication in GF(2**8) */
/* static void mix_columns(state_t *state) { */
/*     uint8_t i, tmp, tm, t; */
/*     for (i = 0; i < 4; ++i) */
/*     { */
/*         t   = (*state)[i][0]; */
/*         tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3]; */
/*         tm  = (*state)[i][0] ^ (*state)[i][1];  tm = xtime(tm);  (*state)[i][0] ^= tm ^ tmp; */
/*         tm  = (*state)[i][1] ^ (*state)[i][2];  tm = xtime(tm);  (*state)[i][1] ^= tm ^ tmp; */
/*         tm  = (*state)[i][2] ^ (*state)[i][3];  tm = xtime(tm);  (*state)[i][2] ^= tm ^ tmp; */
/*         tm  = (*state)[i][3] ^ t;               tm = xtime(tm);  (*state)[i][3] ^= tm ^ tmp; */
/*     } */
/* } */

/* matrix multiplication in GF(2**8) */
static void mix_columns(state_t *state) {
    uint8_t i, a, b, c, d;

    for(i = 0; i < AES_COLUMNS; i++) {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = gmul(a, 0x2) ^ gmul(b, 0x3) ^ gmul(c, 0x1) ^ gmul(d, 0x1);
        (*state)[i][1] = gmul(a, 0x1) ^ gmul(b, 0x2) ^ gmul(c, 0x3) ^ gmul(d, 0x1);
        (*state)[i][2] = gmul(a, 0x1) ^ gmul(b, 0x1) ^ gmul(c, 0x2) ^ gmul(d, 0x3);
        (*state)[i][3] = gmul(a, 0x3) ^ gmul(b, 0x1) ^ gmul(c, 0x1) ^ gmul(d, 0x2);
    }
}

/* multiply with inverse matrix */
static void mix_columns_inv(state_t *state) {
    uint8_t i, a, b, c, d;

    for(i = 0; i < AES_COLUMNS; i++) {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = gmul(a, 0xe) ^ gmul(b, 0xb) ^ gmul(c, 0xd) ^ gmul(d, 0x9);
        (*state)[i][1] = gmul(a, 0x9) ^ gmul(b, 0xe) ^ gmul(c, 0xb) ^ gmul(d, 0xd);
        (*state)[i][2] = gmul(a, 0xd) ^ gmul(b, 0x9) ^ gmul(c, 0xe) ^ gmul(d, 0xb);
        (*state)[i][3] = gmul(a, 0xb) ^ gmul(b, 0xd) ^ gmul(c, 0x9) ^ gmul(d, 0xe);
    }
}

/* AES key schedule for round key generation */
static void key_expansion(uint8_t *round_key, const uint8_t *key) {
    unsigned i, j, k;
    uint8_t prev_word[4];

    for(i = 0; i < AES_KEY_WORD; i++) {
        round_key[i*4 + 0] = key[i*4 + 0];
        round_key[i*4 + 1] = key[i*4 + 1];
        round_key[i*4 + 2] = key[i*4 + 2];
        round_key[i*4 + 3] = key[i*4 + 3];
    }

    for(i = AES_KEY_WORD; i < AES_COLUMNS*(AES_ROUNDS + 1); i++) {
        k = (i - 1)*4;
        prev_word[0] = round_key[k + 0];
        prev_word[1] = round_key[k + 1];
        prev_word[2] = round_key[k + 2];
        prev_word[3] = round_key[k + 3];

        /* if the first word in key then do stuff with the previous key */
        if(i % AES_KEY_WORD == 0) {
            /* rot word */
            {
                const uint8_t tmp = prev_word[0];
                prev_word[0] = prev_word[1];
                prev_word[1] = prev_word[2];
                prev_word[2] = prev_word[3];
                prev_word[3] = tmp;
            }

            /* sbox word */
            prev_word[0] = sbox[prev_word[0]];
            prev_word[1] = sbox[prev_word[1]];
            prev_word[2] = sbox[prev_word[2]];
            prev_word[3] = sbox[prev_word[3]];

            prev_word[0] ^= rcon[i/AES_KEY_WORD];
        }

        /* current word = previous key's word ^ previous word */
        j = i*4;
        k = (i - AES_KEY_WORD)*4;
        round_key[j + 0] = round_key[k + 0] ^ prev_word[0];
        round_key[j + 1] = round_key[k + 1] ^ prev_word[1];
        round_key[j + 2] = round_key[k + 2] ^ prev_word[2];
        round_key[j + 3] = round_key[k + 3] ^ prev_word[3];
    }
}

/* main AES cipher function */
static void cipher(state_t *state, uint8_t *round_key) {
    uint8_t round = 0;

    add_round_key(state, round_key, round);

    for(round = 1; round < AES_ROUNDS+1; round++) {
        sub_bytes(state);
        shift_rows(state);
        if(round != AES_ROUNDS) mix_columns(state);
        add_round_key(state, round_key, round);
    }
}

/* main AES cipher function in reverse */
static void cipher_inv(state_t *state, uint8_t *round_key) {
    uint8_t round;

    add_round_key(state, round_key, AES_ROUNDS);

    /* each round here corresponds to two half-rounds in the normal cipher */
    for(round = AES_ROUNDS-1;; round--) {
        shift_rows_inv(state);
        sub_bytes_inv(state);
        add_round_key(state, round_key, round);
        if(round == 0) break;
        mix_columns_inv(state);
    }
}

static void keygen(uint8_t *key, size_t sz) {
    for(uint8_t i = 0; i < sz; i++)
        key[i] = rand() % 0x100;
}

void ctx_init(struct ctx *ctx, const uint8_t *key, const uint8_t *iv) {
    key_expansion(ctx->round_key, key);
    memcpy(ctx->iv, iv, sizeof ctx->iv);
}

void cbc_encrypt_buf(struct ctx *ctx, uint8_t *buf, size_t sz) {
    size_t i;
    uint8_t *iv = ctx->iv;

    for(i = 0; i < sz; i += AES_BLOCKLEN) {
        xor_block(buf, iv);
        cipher((state_t *)buf, ctx->round_key);
        iv = buf;
        buf += AES_BLOCKLEN;
    }

    memcpy(ctx->iv, iv, AES_BLOCKLEN);
}

void cbc_decrypt_buf(struct ctx *ctx, uint8_t *buf, size_t sz) {
    size_t i;
    uint8_t iv[AES_BLOCKLEN];

    for(i = 0; i < sz; i += AES_BLOCKLEN) {
        memcpy(iv, buf, AES_BLOCKLEN);
        cipher_inv((state_t *)buf, ctx->round_key);
        xor_block(buf, ctx->iv);
        memcpy(ctx->iv, iv, AES_BLOCKLEN);
        buf += AES_BLOCKLEN;
    }
}

/* adds PKCS #7 padding to buf
 * sz is size excluding padding
 * returns padded size */
size_t pad_pkcs7(uint8_t *buf, size_t blocksz, size_t sz) {
    size_t padsz = blocksz - (sz + 1) % blocksz + 1;
    memset(buf + sz, padsz, padsz);
    return (sz+1 + 0xf) & ~0xf;
}

/* removes PKCS #7 from buf
 * sz is size including padding
 * returns unpadded size */
size_t unpad_pkcs7(uint8_t *buf, size_t sz) {
    uint8_t padsz = buf[sz-1];
    /* TODO: error */
    if(padsz > AES_BLOCKLEN) return (size_t)-1;
    memset(buf + sz - padsz, 0, padsz);
    return sz - padsz;
}

static void print_hex(uint8_t *buf, size_t sz) {
    size_t i;
    for(i = 0; i < sz; i++)
        printf("%02X", buf[i]);
    printf("\n");
}

void algo_aes(void) {
    char buf[256] = { 0 };
    size_t len;
    struct ctx ctx;
    uint8_t key[AES_KEYLEN], iv[AES_BLOCKLEN];

    keygen(key, sizeof key);
    keygen(iv, sizeof key);
    ctx_init(&ctx, key, iv);

    printf("plaintext: ");
    fgets(buf, sizeof buf - 1, stdin);
    buf[len = strcspn(buf, "\n")] = '\0';
    len = pad_pkcs7((uint8_t *)buf, AES_BLOCKLEN, len);

    /* encryption */
    cbc_encrypt_buf(&ctx, (uint8_t *)buf, len);
    printf("ciphertext: "); print_hex((uint8_t *)buf, len);
    printf("key: "); print_hex((uint8_t *)key, sizeof key);
    printf("iv: "); print_hex((uint8_t *)iv, sizeof iv);

    /* decryption */
    memcpy(ctx.iv, iv, AES_BLOCKLEN);
    cbc_decrypt_buf(&ctx, (uint8_t *)buf, len);
    unpad_pkcs7((uint8_t *)buf, len);
    printf("decrypted: %s\n", buf);
}
