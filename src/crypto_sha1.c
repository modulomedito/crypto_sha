//==================================================================================================
/// @file       crypto_sha1.c
/// @author     modulomedito (chcchc1995@outlook.com)
/// @brief
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==================================================================================================
//==================================================================================================
// INCLUDE
//==================================================================================================
#include "crypto_sha1.h"
#include <string.h>

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

//==================================================================================================
// PRIVATE VARIABLE DEFINITION
//==================================================================================================
static u32 crypto_sha1__circular_shift(const u32 nbits, const u32 word);
static void crypto_sha1__Ctx_pad_block(crypto_sha1__Ctx *self);
static void crypto_sha1__Ctx_process_block(crypto_sha1__Ctx *self);

//==================================================================================================
// PUBLIC VARIABLE DEFINITION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DEFINITION
//==================================================================================================
crypto_sha1__Ret crypto_sha1__compute(
    const u8 *data_ref,
    u32 data_len,
    u8 *hash_mut,
    u32 hash_buf_size
) {
    if ((data_ref == NULL) || //
        (hash_mut == NULL) || //
        (data_len == 0) || //
        (hash_buf_size < CRYPTO_SHA1__HASH_SIZE)) {
        return crypto_sha1__Ret_InvalidArg;
    }

    crypto_sha1__Ctx sha1_ctx;
    crypto_sha1__Ret ret;

    ret = crypto_sha1__Ctx_init(&sha1_ctx);
    if (ret != crypto_sha1__Ret_Ok) {
        return ret;
    }

    ret = crypto_sha1__Ctx_update(&sha1_ctx, data_ref, data_len);
    if (ret != crypto_sha1__Ret_Ok) {
        return ret;
    }

    ret = crypto_sha1__Ctx_finalize(&sha1_ctx, hash_mut, hash_buf_size);
    if (ret != crypto_sha1__Ret_Ok) {
        return ret;
    }

    return crypto_sha1__Ret_Ok;
}

crypto_sha1__Ret crypto_sha1__Ctx_init(crypto_sha1__Ctx *self) {
    if (self == NULL) {
        return crypto_sha1__Ret_InvalidArg;
    }

    self->length_low = 0;
    self->length_high = 0;
    self->msg_block_index = 0;

    self->intermediate_hash_buf[0] = 0x67452301;
    self->intermediate_hash_buf[1] = 0xefcdab89;
    self->intermediate_hash_buf[2] = 0x98badcfe;
    self->intermediate_hash_buf[3] = 0x10325476;
    self->intermediate_hash_buf[4] = 0xc3d2e1f0;

    self->flags = 0;

    return crypto_sha1__Ret_Ok;
}

crypto_sha1__Ret crypto_sha1__Ctx_update(crypto_sha1__Ctx *self, const u8 *data_ref, u32 data_len) {
    if (data_len == 0) {
        return crypto_sha1__Ret_Ok;
    }

    if ((self == NULL) || (data_ref == NULL)) {
        return crypto_sha1__Ret_InvalidArg;
    }

    if ((self->flags & CRYPTO_SHA1__FLAG_FINISHED) != 0) {
        self->flags |= CRYPTO_SHA1__FLAG_ERROR;
        return crypto_sha1__Ret_Error;
    }

    if ((self->flags & CRYPTO_SHA1__FLAG_ERROR) != 0) {
        return crypto_sha1__Ret_Error;
    }

    u32 remain_len = data_len;
    u32 data_idx = 0;

    while ((remain_len != 0) && (self->flags == 0)) {
        self->msg_block_buf[self->msg_block_index] = data_ref[data_idx];

        self->msg_block_index += 1;
        self->length_low += 8;

        if (self->length_low == 0) {
            self->length_high += 1;

            if (self->length_high == 0) {
                self->flags |= CRYPTO_SHA1__FLAG_ERROR;
            }
        }

        if (self->msg_block_index == 64) {
            crypto_sha1__Ctx_process_block(self);
        }

        data_idx += 1;
        remain_len -= 1;
    }

    return crypto_sha1__Ret_Ok;
}

crypto_sha1__Ret crypto_sha1__Ctx_finalize(
    crypto_sha1__Ctx *self,
    u8 *hash_mut,
    u32 hash_buf_size
) {
    u8 i;
    u16 rsh_bit;

    if ((self == NULL) || (hash_mut == NULL)) {
        return crypto_sha1__Ret_InvalidArg;
    }

    if (hash_buf_size < CRYPTO_SHA1__HASH_SIZE) {
        return crypto_sha1__Ret_InvalidArg;
    }

    if ((self->flags & CRYPTO_SHA1__FLAG_ERROR) != 0) {
        return crypto_sha1__Ret_Error;
    }

    if ((self->flags & CRYPTO_SHA1__FLAG_FINISHED) == 0) {
        crypto_sha1__Ctx_pad_block(self);

        for (i = 0; i < 64; i++) {
            self->msg_block_buf[i] = 0;
        }
        self->length_low = 0;
        self->length_high = 0;
        self->flags |= CRYPTO_SHA1__FLAG_FINISHED;
    }

    for (i = 0; i < CRYPTO_SHA1__HASH_SIZE; i++) {
        rsh_bit = (8 * (3 - (i & 0x03)));
        hash_mut[i] = (self->intermediate_hash_buf[i >> 2] >> rsh_bit) & 0xff;
    }

    return crypto_sha1__Ret_Ok;
}

//==================================================================================================
// PRIVATE FUNCTION DEFINITION
//==================================================================================================
static u32 crypto_sha1__circular_shift(const u32 nbits, const u32 u32in) {
    return ((u32in << nbits) | (u32in >> (32 - nbits)));
}

static void crypto_sha1__Ctx_process_block(crypto_sha1__Ctx *self) {
    const u32 const_val_tbl[4] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};
    u8 x;
    u32 temp;
    u32 u32_buf[80];
    u32 u32a, u32b, u32c, u32d, u32e;

    for (x = 0; x < 16; x++) {
        u32_buf[x] = ((u32)self->msg_block_buf[x * 4]) << 0x18;
        u32_buf[x] |= ((u32)self->msg_block_buf[(x * 4) + 1]) << 0x10;
        u32_buf[x] |= ((u32)self->msg_block_buf[(x * 4) + 2]) << 0x08;
        u32_buf[x] |= ((u32)self->msg_block_buf[(x * 4) + 3]);
    }

    for (x = 16; x < 80; x++) {
        u32 shift_in = (u32_buf[x - 3] ^ u32_buf[x - 8] ^ u32_buf[x - 14] ^ u32_buf[x - 16]);
        u32_buf[x] = crypto_sha1__circular_shift(1, shift_in);
    }

    u32a = self->intermediate_hash_buf[0];
    u32b = self->intermediate_hash_buf[1];
    u32c = self->intermediate_hash_buf[2];
    u32d = self->intermediate_hash_buf[3];
    u32e = self->intermediate_hash_buf[4];

    for (x = 0; x < 20; x++) {
        temp = crypto_sha1__circular_shift(5, u32a) + //
               ((u32b & u32c) | ((~u32b) & u32d)) + //
               u32e + u32_buf[x] + const_val_tbl[0];

        u32e = u32d;
        u32d = u32c;
        u32c = crypto_sha1__circular_shift(30, u32b);
        u32b = u32a;
        u32a = temp;
    }

    for (x = 20; x < 40; x++) {
        temp = crypto_sha1__circular_shift(5, u32a) + //
               (u32b ^ u32c ^ u32d) + //
               u32e + u32_buf[x] + const_val_tbl[1];

        u32e = u32d;
        u32d = u32c;
        u32c = crypto_sha1__circular_shift(30, u32b);
        u32b = u32a;
        u32a = temp;
    }

    for (x = 40; x < 60; x++) {
        temp = crypto_sha1__circular_shift(5, u32a) + //
               ((u32b & u32c) | (u32b & u32d) | (u32c & u32d)) + //
               u32e + u32_buf[x] + const_val_tbl[2];

        u32e = u32d;
        u32d = u32c;
        u32c = crypto_sha1__circular_shift(30, u32b);
        u32b = u32a;
        u32a = temp;
    }

    for (x = 60; x < 80; x++) {
        temp = crypto_sha1__circular_shift(5, u32a) + //
               (u32b ^ u32c ^ u32d) + //
               u32e + u32_buf[x] + const_val_tbl[3];
        u32e = u32d;
        u32d = u32c;
        u32c = crypto_sha1__circular_shift(30, u32b);
        u32b = u32a;
        u32a = temp;
    }

    self->intermediate_hash_buf[0] += u32a;
    self->intermediate_hash_buf[1] += u32b;
    self->intermediate_hash_buf[2] += u32c;
    self->intermediate_hash_buf[3] += u32d;
    self->intermediate_hash_buf[4] += u32e;

    self->msg_block_index = 0;
}

static void crypto_sha1__Ctx_pad_block(crypto_sha1__Ctx *self) {
    if (self->msg_block_index > 55) {
        self->msg_block_buf[self->msg_block_index] = 0x80;
        self->msg_block_index += 1;

        while (self->msg_block_index < 64) {
            self->msg_block_buf[self->msg_block_index] = 0;
            self->msg_block_index += 1;
        }

        crypto_sha1__Ctx_process_block(self);

        while (self->msg_block_index < 56) {
            self->msg_block_buf[self->msg_block_index] = 0;
            self->msg_block_index += 1;
        }
    } else {
        self->msg_block_buf[self->msg_block_index] = 0x80;
        self->msg_block_index += 1;

        while (self->msg_block_index < 56) {
            self->msg_block_buf[self->msg_block_index] = 0;
            self->msg_block_index += 1;
        }
    }

    self->msg_block_buf[56] = self->length_high >> 0x18;
    self->msg_block_buf[57] = self->length_high >> 0x10;
    self->msg_block_buf[58] = self->length_high >> 0x08;
    self->msg_block_buf[59] = self->length_high;
    self->msg_block_buf[60] = self->length_low >> 0x18;
    self->msg_block_buf[61] = self->length_low >> 0x10;
    self->msg_block_buf[62] = self->length_low >> 0x08;
    self->msg_block_buf[63] = self->length_low;

    crypto_sha1__Ctx_process_block(self);
}

//==================================================================================================
// TEST
//==================================================================================================
