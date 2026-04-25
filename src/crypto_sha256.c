//==================================================================================================
/// @file       crypto_sha256.c
/// @author     modulomedito (chcchc1995@outlook.com)
/// @brief
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==================================================================================================
//==================================================================================================
// INCLUDE
//==================================================================================================
#include "crypto_sha256.h"

//==================================================================================================
// IMPORTED SWITCH CHECK
//==================================================================================================

//==================================================================================================
// PRIVATE DEFINE
//==================================================================================================

//==================================================================================================
// PRIVATE TYPEDEF
//==================================================================================================

//==================================================================================================
// PRIVATE ENUM
//==================================================================================================

//==================================================================================================
// PRIVATE STRUCT
//==================================================================================================

//==================================================================================================
// PRIVATE UNION
//==================================================================================================

//==================================================================================================
// PRIVATE FUNCTION DECLARATION
//==================================================================================================
static u8 crypto_sha256__shb(u32 x, u32 n);
static u32 crypto_sha256__shw(u32 x, u32 n);
static u32 crypto_sha256__r(u32 x, u8 n);
static u32 crypto_sha256__ch(u32 x, u32 y, u32 z);
static u32 crypto_sha256__ma(u32 x, u32 y, u32 z);
static u32 crypto_sha256__s0(u32 x);
static u32 crypto_sha256__s1(u32 x);
static u32 crypto_sha256__g0(u32 x);
static u32 crypto_sha256__g1(u32 x);
static u32 crypto_sha256__word(u8* c_mut);

static void crypto_sha256__Ctx_addbits(crypto_sha256__Ctx* self, u32 n);
static void crypto_sha256__Ctx_hash(crypto_sha256__Ctx* self);

//==================================================================================================
// PRIVATE VARIABLE DEFINITION
//==================================================================================================
static const u32 crypto_sha256__k_tbl[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

//==================================================================================================
// PUBLIC VARIABLE DEFINITION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DEFINITION
//==================================================================================================
void crypto_sha256__compute(const u8* data_ref, u32 len, u8* hash_mut) {
    crypto_sha256__Ctx ctx;

    crypto_sha256__Ctx_init(&ctx);
    crypto_sha256__Ctx_update(&ctx, data_ref, len);
    crypto_sha256__Ctx_finalize(&ctx, hash_mut);
}

void crypto_sha256__Ctx_init(crypto_sha256__Ctx* self) {
    self->len = 0;
    self->bits_buf[0] = 0;
    self->bits_buf[1] = 0;
    self->hash_buf[0] = 0x6a09e667;
    self->hash_buf[1] = 0xbb67ae85;
    self->hash_buf[2] = 0x3c6ef372;
    self->hash_buf[3] = 0xa54ff53a;
    self->hash_buf[4] = 0x510e527f;
    self->hash_buf[5] = 0x9b05688c;
    self->hash_buf[6] = 0x1f83d9ab;
    self->hash_buf[7] = 0x5be0cd19;
}

void crypto_sha256__Ctx_update(crypto_sha256__Ctx* self, const u8* data_ref, u32 len) {
    if (data_ref == NULL) {
        return;
    }
    if (self->len >= sizeof(self->data_buf)) {
        return;
    }

    for (u32 i = 0; i < len; i++) {
        self->data_buf[self->len++] = data_ref[i];
        if (self->len == sizeof(self->data_buf)) {
            crypto_sha256__Ctx_hash(self);
            crypto_sha256__Ctx_addbits(self, 8 * sizeof(self->data_buf));
            self->len = 0;
        }
    }
}

void crypto_sha256__Ctx_finalize(crypto_sha256__Ctx* self, u8* hash_mut) {
    u32 i, j;

    j = self->len % sizeof(self->data_buf);
    self->data_buf[j] = 0x80;
    for (i = j + 1; i < sizeof(self->data_buf); i++) {
        self->data_buf[i] = 0x00;
    }

    if (self->len > 55) {
        crypto_sha256__Ctx_hash(self);
        for (j = 0; j < sizeof(self->data_buf); j++) {
            self->data_buf[j] = 0x00;
        }
    }

    crypto_sha256__Ctx_addbits(self, self->len * 8);
    self->data_buf[63] = crypto_sha256__shb(self->bits_buf[0], 0);
    self->data_buf[62] = crypto_sha256__shb(self->bits_buf[0], 8);
    self->data_buf[61] = crypto_sha256__shb(self->bits_buf[0], 16);
    self->data_buf[60] = crypto_sha256__shb(self->bits_buf[0], 24);
    self->data_buf[59] = crypto_sha256__shb(self->bits_buf[1], 0);
    self->data_buf[58] = crypto_sha256__shb(self->bits_buf[1], 8);
    self->data_buf[57] = crypto_sha256__shb(self->bits_buf[1], 16);
    self->data_buf[56] = crypto_sha256__shb(self->bits_buf[1], 24);
    crypto_sha256__Ctx_hash(self);

    if (hash_mut != NULL) {
        for (i = 0, j = 24; i < 4; i++, j -= 8) {
            hash_mut[i + 0] = crypto_sha256__shb(self->hash_buf[0], j);
            hash_mut[i + 4] = crypto_sha256__shb(self->hash_buf[1], j);
            hash_mut[i + 8] = crypto_sha256__shb(self->hash_buf[2], j);
            hash_mut[i + 12] = crypto_sha256__shb(self->hash_buf[3], j);
            hash_mut[i + 16] = crypto_sha256__shb(self->hash_buf[4], j);
            hash_mut[i + 20] = crypto_sha256__shb(self->hash_buf[5], j);
            hash_mut[i + 24] = crypto_sha256__shb(self->hash_buf[6], j);
            hash_mut[i + 28] = crypto_sha256__shb(self->hash_buf[7], j);
        }
    }
}

//==================================================================================================
// PRIVATE FUNCTION DEFINITION
//==================================================================================================
static u8 crypto_sha256__shb(u32 x, u32 n) {
    return ((x >> (n & 31)) & 0xff);
}

static u32 crypto_sha256__shw(u32 x, u32 n) {
    return ((x << (n & 31)) & 0xffffffff);
}

static u32 crypto_sha256__r(u32 x, u8 n) {
    return ((x >> n) | crypto_sha256__shw(x, 32 - n));
}

static u32 crypto_sha256__ch(u32 x, u32 y, u32 z) {
    return ((x & y) ^ ((~x) & z));
}

static u32 crypto_sha256__ma(u32 x, u32 y, u32 z) {
    return ((x & y) ^ (x & z) ^ (y & z));
}

static u32 crypto_sha256__s0(u32 x) {
    return (crypto_sha256__r(x, 2) ^ crypto_sha256__r(x, 13) ^ crypto_sha256__r(x, 22));
}

static u32 crypto_sha256__s1(u32 x) {
    return (crypto_sha256__r(x, 6) ^ crypto_sha256__r(x, 11) ^ crypto_sha256__r(x, 25));
}

static u32 crypto_sha256__g0(u32 x) {
    return (crypto_sha256__r(x, 7) ^ crypto_sha256__r(x, 18) ^ (x >> 3));
}

static u32 crypto_sha256__g1(u32 x) {
    return (crypto_sha256__r(x, 17) ^ crypto_sha256__r(x, 19) ^ (x >> 10));
}

static u32 crypto_sha256__word(u8* c_mut) {
    return (
        crypto_sha256__shw(c_mut[0], 0x18) | //
        crypto_sha256__shw(c_mut[1], 0x10) | //
        crypto_sha256__shw(c_mut[2], 0x08) | //
        (c_mut[3])
    );
}

static void crypto_sha256__Ctx_addbits(crypto_sha256__Ctx* self, u32 n) {
    if (self->bits_buf[0] > (0xffffffff - n)) {
        self->bits_buf[1] = (self->bits_buf[1] + 1) & 0xFFFFFFFF;
    }
    self->bits_buf[0] = (self->bits_buf[0] + n) & 0xFFFFFFFF;
}

static void crypto_sha256__Ctx_hash(crypto_sha256__Ctx* self) {
    u32 a, b, c, d, e, f, g, h;
    u32 temp_buf[2];

    a = self->hash_buf[0];
    b = self->hash_buf[1];
    c = self->hash_buf[2];
    d = self->hash_buf[3];
    e = self->hash_buf[4];
    f = self->hash_buf[5];
    g = self->hash_buf[6];
    h = self->hash_buf[7];

    for (u32 i = 0; i < 64; i++) {
        if (i < 16) {
            self->u32_buf[i] = crypto_sha256__word(&self->data_buf[crypto_sha256__shw(i, 2)]);
        } else {
            self->u32_buf[i] = crypto_sha256__g1(self->u32_buf[i - 2]) + //
                               self->u32_buf[i - 7] + //
                               crypto_sha256__g0(self->u32_buf[i - 15]) + //
                               self->u32_buf[i - 16];
        }

        temp_buf[0] = h + crypto_sha256__s1(e) + //
                      crypto_sha256__ch(e, f, g) + //
                      crypto_sha256__k_tbl[i] + //
                      self->u32_buf[i];
        temp_buf[1] = crypto_sha256__s0(a) + crypto_sha256__ma(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + temp_buf[0];
        d = c;
        c = b;
        b = a;
        a = temp_buf[0] + temp_buf[1];
    }

    self->hash_buf[0] += a;
    self->hash_buf[1] += b;
    self->hash_buf[2] += c;
    self->hash_buf[3] += d;
    self->hash_buf[4] += e;
    self->hash_buf[5] += f;
    self->hash_buf[6] += g;
    self->hash_buf[7] += h;
}

//==================================================================================================
// TEST
//==================================================================================================
#include <string.h>

static i32 crypto_sha256__test_tc1(void) {
    u8 data_buf[] = {"abc"};
    u8 hash_buf[CRYPTO_SHA256__BLOCK_U8_SIZE];
    u8 expected_hash_buf[CRYPTO_SHA256__BLOCK_U8_SIZE] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, //
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, //
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, //
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad, //
    };

    crypto_sha256__compute(data_buf, strlen((const ichar*)data_buf), hash_buf);
    if (memcmp(hash_buf, expected_hash_buf, CRYPTO_SHA256__BLOCK_U8_SIZE) != 0) {
        return __LINE__;
    }

    crypto_sha256__Ctx ctx;
    crypto_sha256__Ctx_init(&ctx);
    crypto_sha256__Ctx_update(&ctx, &data_buf[0], strlen((const ichar*)data_buf) / 2);
    crypto_sha256__Ctx_update(
        &ctx,
        &data_buf[strlen((const ichar*)data_buf) / 2],
        strlen((const ichar*)data_buf) - (strlen((const ichar*)data_buf) / 2)
    );
    crypto_sha256__Ctx_finalize(&ctx, hash_buf);
    if (memcmp(hash_buf, expected_hash_buf, CRYPTO_SHA256__BLOCK_U8_SIZE) != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_sha256__test_tc2(void) {
    u8 data_buf[] = {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
    u8 hash_buf[CRYPTO_SHA256__BLOCK_U8_SIZE];
    u8 expected_hash_buf[CRYPTO_SHA256__BLOCK_U8_SIZE] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, //
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39, //
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, //
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1, //
    };

    crypto_sha256__compute(data_buf, strlen((const ichar*)data_buf), hash_buf);
    if (memcmp(hash_buf, expected_hash_buf, CRYPTO_SHA256__BLOCK_U8_SIZE) != 0) {
        return __LINE__;
    }

    crypto_sha256__Ctx ctx;
    crypto_sha256__Ctx_init(&ctx);
    crypto_sha256__Ctx_update(&ctx, &data_buf[0], strlen((const ichar*)data_buf) / 2);
    crypto_sha256__Ctx_update(
        &ctx,
        &data_buf[strlen((const ichar*)data_buf) / 2],
        strlen((const ichar*)data_buf) - (strlen((const ichar*)data_buf) / 2)
    );
    crypto_sha256__Ctx_finalize(&ctx, hash_buf);
    if (memcmp(hash_buf, expected_hash_buf, CRYPTO_SHA256__BLOCK_U8_SIZE) != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_sha256__test_tc3(void) {
    u8 data_buf[] = {
        "bhn5bjmoniertqea40wro2upyflkydsibsk8ylkmgbvwi420t44cq034eou1szc1k0mk46oeb7ktzmlxqkbte2sy"};
    u8 hash_buf[CRYPTO_SHA256__BLOCK_U8_SIZE];
    u8 expected_hash_buf[CRYPTO_SHA256__BLOCK_U8_SIZE] = {
        0x90, 0x85, 0xdf, 0x2f, 0x02, 0xe0, 0xcc, 0x45, //
        0x59, 0x28, 0xd0, 0xf5, 0x1b, 0x27, 0xb4, 0xbf, //
        0x1d, 0x9c, 0xd2, 0x60, 0xa6, 0x6e, 0xd1, 0xfd, //
        0xa1, 0x1b, 0x0a, 0x3f, 0xf5, 0x75, 0x6d, 0x99, //
    };

    crypto_sha256__compute(data_buf, strlen((const ichar*)data_buf), hash_buf);
    if (memcmp(hash_buf, expected_hash_buf, CRYPTO_SHA256__BLOCK_U8_SIZE) != 0) {
        return __LINE__;
    }

    crypto_sha256__Ctx ctx;
    crypto_sha256__Ctx_init(&ctx);
    crypto_sha256__Ctx_update(&ctx, &data_buf[0], strlen((const ichar*)data_buf) / 2);
    crypto_sha256__Ctx_update(
        &ctx,
        &data_buf[strlen((const ichar*)data_buf) / 2],
        strlen((const ichar*)data_buf) - (strlen((const ichar*)data_buf) / 2)
    );
    crypto_sha256__Ctx_finalize(&ctx, hash_buf);
    if (memcmp(hash_buf, expected_hash_buf, CRYPTO_SHA256__BLOCK_U8_SIZE) != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_sha256__test_tc4(void) {
    u8 data_buf[] = {""};
    u8 hash_buf[CRYPTO_SHA256__BLOCK_U8_SIZE];
    u8 expected_hash_buf[CRYPTO_SHA256__BLOCK_U8_SIZE] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, //
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, //
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, //
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55, //
    };

    crypto_sha256__compute(data_buf, strlen((const ichar*)data_buf), hash_buf);
    if (memcmp(hash_buf, expected_hash_buf, CRYPTO_SHA256__BLOCK_U8_SIZE) != 0) {
        return __LINE__;
    }

    crypto_sha256__Ctx ctx;
    crypto_sha256__Ctx_init(&ctx);
    crypto_sha256__Ctx_update(&ctx, &data_buf[0], strlen((const ichar*)data_buf) / 2);
    crypto_sha256__Ctx_update(
        &ctx,
        &data_buf[strlen((const ichar*)data_buf) / 2],
        strlen((const ichar*)data_buf) - (strlen((const ichar*)data_buf) / 2)
    );
    crypto_sha256__Ctx_finalize(&ctx, hash_buf);
    if (memcmp(hash_buf, expected_hash_buf, CRYPTO_SHA256__BLOCK_U8_SIZE) != 0) {
        return __LINE__;
    }

    return 0;
}

i32 crypto_sha256__test(void) {
    i32 result;

    result = crypto_sha256__test_tc1();
    if (result != 0) {
        return result;
    }
    result = crypto_sha256__test_tc2();
    if (result != 0) {
        return result;
    }
    result = crypto_sha256__test_tc3();
    if (result != 0) {
        return result;
    }
    result = crypto_sha256__test_tc4();
    if (result != 0) {
        return result;
    }

    return 0;
}
