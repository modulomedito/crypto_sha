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
#include <stdio.h>
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
static u32 crypto_sha1_circular_shift(const u32 nbits, const u32 u32in);
static void crypto_sha1_Handle_pad_block(crypto_sha1_Handle *self);
static void crypto_sha1_Handle_process_block(crypto_sha1_Handle *self);

//==================================================================================================
// PUBLIC VARIABLE DEFINITION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DEFINITION
//==================================================================================================
crypto_sha1_Ret crypto_sha1_compute(
    const u8 *data_ref,
    u32 data_len,
    u8 *hash_mut,
    u32 hash_buf_size
) {
    if ((data_ref == NULL) || //
        (hash_mut == NULL) || //
        (hash_buf_size < CRYPTO_SHA1_HASH_SIZE)) {
        return crypto_sha1_Ret_InvalidArg;
    }

    crypto_sha1_Handle sha1_ctx;
    crypto_sha1_Ret ret;

    ret = crypto_sha1_Handle_init(&sha1_ctx);
    if (ret != crypto_sha1_Ret_Ok) {
        return ret;
    }

    ret = crypto_sha1_Handle_update(&sha1_ctx, data_ref, data_len);
    if (ret != crypto_sha1_Ret_Ok) {
        return ret;
    }

    ret = crypto_sha1_Handle_finalize(&sha1_ctx, hash_mut, hash_buf_size);
    if (ret != crypto_sha1_Ret_Ok) {
        return ret;
    }

    return crypto_sha1_Ret_Ok;
}

crypto_sha1_Ret crypto_sha1_Handle_init(crypto_sha1_Handle *self) {
    if (self == NULL) {
        return crypto_sha1_Ret_InvalidArg;
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

    return crypto_sha1_Ret_Ok;
}

crypto_sha1_Ret crypto_sha1_Handle_update(
    crypto_sha1_Handle *self,
    const u8 *data_ref,
    u32 data_len
) {
    if (data_len == 0) {
        return crypto_sha1_Ret_Ok;
    }

    if ((self == NULL) || (data_ref == NULL)) {
        return crypto_sha1_Ret_InvalidArg;
    }

    if ((self->flags & CRYPTO_SHA1_FLAG_FINISHED) != 0) {
        self->flags |= CRYPTO_SHA1_FLAG_ERROR;
        return crypto_sha1_Ret_Error;
    }

    if ((self->flags & CRYPTO_SHA1_FLAG_ERROR) != 0) {
        return crypto_sha1_Ret_Error;
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
                self->flags |= CRYPTO_SHA1_FLAG_ERROR;
            }
        }

        if (self->msg_block_index == 64) {
            crypto_sha1_Handle_process_block(self);
        }

        data_idx += 1;
        remain_len -= 1;
    }

    return crypto_sha1_Ret_Ok;
}

crypto_sha1_Ret crypto_sha1_Handle_finalize(
    crypto_sha1_Handle *self,
    u8 *hash_mut,
    u32 hash_buf_size
) {
    u8 i;
    u16 rsh_bit;

    if ((self == NULL) || (hash_mut == NULL)) {
        return crypto_sha1_Ret_InvalidArg;
    }

    if (hash_buf_size < CRYPTO_SHA1_HASH_SIZE) {
        return crypto_sha1_Ret_InvalidArg;
    }

    if ((self->flags & CRYPTO_SHA1_FLAG_ERROR) != 0) {
        return crypto_sha1_Ret_Error;
    }

    if ((self->flags & CRYPTO_SHA1_FLAG_FINISHED) == 0) {
        crypto_sha1_Handle_pad_block(self);

        for (i = 0; i < 64; i++) {
            self->msg_block_buf[i] = 0;
        }
        self->length_low = 0;
        self->length_high = 0;
        self->flags |= CRYPTO_SHA1_FLAG_FINISHED;
    }

    for (i = 0; i < CRYPTO_SHA1_HASH_SIZE; i++) {
        rsh_bit = (8 * (3 - (i & 0x03)));
        hash_mut[i] = (self->intermediate_hash_buf[i >> 2] >> rsh_bit) & 0xff;
    }

    return crypto_sha1_Ret_Ok;
}

//==================================================================================================
// PRIVATE FUNCTION DEFINITION
//==================================================================================================
static u32 crypto_sha1_circular_shift(const u32 nbits, const u32 u32in) {
    const u32 rshift = 32 - nbits;
    const u32 mask = 0xffffffff >> nbits; // Bits that stay in range after << nbits
    return ((u32in & mask) << nbits) | (u32in >> rshift);
}

static void crypto_sha1_Handle_process_block(crypto_sha1_Handle *self) {
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
        u32_buf[x] = crypto_sha1_circular_shift(1, shift_in);
    }

    u32a = self->intermediate_hash_buf[0];
    u32b = self->intermediate_hash_buf[1];
    u32c = self->intermediate_hash_buf[2];
    u32d = self->intermediate_hash_buf[3];
    u32e = self->intermediate_hash_buf[4];

    for (x = 0; x < 20; x++) {
        temp = (u32)(((u64)crypto_sha1_circular_shift(5, u32a) + //
                      (u64)((u32b & u32c) | ((~u32b) & u32d)) + //
                      (u64)u32e + (u64)u32_buf[x] + (u64)const_val_tbl[0]) &
                     0xffffffff);

        u32e = u32d;
        u32d = u32c;
        u32c = crypto_sha1_circular_shift(30, u32b);
        u32b = u32a;
        u32a = temp;
    }

    for (x = 20; x < 40; x++) {
        temp = (u32)(((u64)crypto_sha1_circular_shift(5, u32a) + //
                      (u64)(u32b ^ u32c ^ u32d) + //
                      (u64)u32e + (u64)u32_buf[x] + (u64)const_val_tbl[1]) &
                     0xffffffff);

        u32e = u32d;
        u32d = u32c;
        u32c = crypto_sha1_circular_shift(30, u32b);
        u32b = u32a;
        u32a = temp;
    }

    for (x = 40; x < 60; x++) {
        temp = (u32)(((u64)crypto_sha1_circular_shift(5, u32a) + //
                      (u64)((u32b & u32c) | (u32b & u32d) | (u32c & u32d)) + //
                      (u64)u32e + (u64)u32_buf[x] + (u64)const_val_tbl[2]) &
                     0xffffffff);

        u32e = u32d;
        u32d = u32c;
        u32c = crypto_sha1_circular_shift(30, u32b);
        u32b = u32a;
        u32a = temp;
    }

    for (x = 60; x < 80; x++) {
        temp = (u32)(((u64)crypto_sha1_circular_shift(5, u32a) + //
                      (u64)(u32b ^ u32c ^ u32d) + //
                      (u64)u32e + (u64)u32_buf[x] + (u64)const_val_tbl[3]) &
                     0xffffffff);
        u32e = u32d;
        u32d = u32c;
        u32c = crypto_sha1_circular_shift(30, u32b);
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

static void crypto_sha1_Handle_pad_block(crypto_sha1_Handle *self) {
    if (self->msg_block_index > 55) {
        self->msg_block_buf[self->msg_block_index] = 0x80;
        self->msg_block_index += 1;

        while (self->msg_block_index < 64) {
            self->msg_block_buf[self->msg_block_index] = 0;
            self->msg_block_index += 1;
        }

        crypto_sha1_Handle_process_block(self);

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

    crypto_sha1_Handle_process_block(self);
}

//==================================================================================================
// TEST
//==================================================================================================
#include <string.h>

#define ENABLE_DEBUG_PRINT (0)

#if defined(ENABLE_DEBUG_PRINT) && (ENABLE_DEBUG_PRINT > 0)
#include <stdio.h>
#endif // ENABLE_DEBUG_PRINT

// Binary-safe memcmp for test assertions (not string, not flagged by MISRA string checkers)
static inline i32 crypto_sha1_memcmp(const u8 *a_ref, const u8 *b_ref, u32 len) {
    for (u32 i = 0; i < len; i++) {
        if (a_ref[i] != b_ref[i]) {
            return (i32)(a_ref[i] - b_ref[i]);
        }
    }
    return 0;
}

static i32 crypto_sha1_test_tc1(void) {
    const u8 string_buf[] = "";
    const u8 expect_buf[] = {0xda, 0x39, 0xa3, 0xee, //
                             0x5e, 0x6b, 0x4b, 0x0d, //
                             0x32, 0x55, 0xbf, 0xef, //
                             0x95, 0x60, 0x18, 0x90, //
                             0xaf, 0xd8, 0x07, 0x09};

    u8 hash_buf[20] = {0};

    crypto_sha1_Ret ret =
        crypto_sha1_compute(string_buf, (u32)(sizeof(string_buf) - 1), hash_buf, sizeof(hash_buf));

    if (ret != crypto_sha1_Ret_Ok) {
        return __LINE__;
    }

    i32 cmp = crypto_sha1_memcmp(expect_buf, hash_buf, sizeof(expect_buf));
    if (cmp != 0) {
#if defined(ENABLE_DEBUG_PRINT) && (ENABLE_DEBUG_PRINT > 0)
        for (u32 i = 0; i < sizeof(hash_buf); i++) {
            printf("hash[%d] = 0x%02x\n", i, hash_buf[i]);
        }
#endif // ENABLE_DEBUG_PRINT
        return __LINE__;
    }

    return 0;
}

static i32 crypto_sha1_test_tc2(void) {
    const u8 string_buf[] = "abc";
    const u8 expect_buf[] = {0xa9, 0x99, 0x3e, 0x36, //
                             0x47, 0x06, 0x81, 0x6a, //
                             0xba, 0x3e, 0x25, 0x71, //
                             0x78, 0x50, 0xc2, 0x6c, //
                             0x9c, 0xd0, 0xd8, 0x9d};

    u8 hash_buf[20] = {0};

    crypto_sha1_Ret ret =
        crypto_sha1_compute(string_buf, (u32)(sizeof(string_buf) - 1), hash_buf, sizeof(hash_buf));

    if (ret != crypto_sha1_Ret_Ok) {
        return __LINE__;
    }

    i32 cmp = crypto_sha1_memcmp(expect_buf, hash_buf, sizeof(expect_buf));
    if (cmp != 0) {
#if defined(ENABLE_DEBUG_PRINT) && (ENABLE_DEBUG_PRINT > 0)
        for (u32 i = 0; i < sizeof(hash_buf); i++) {
            printf("hash[%d] = 0x%02x\n", i, hash_buf[i]);
        }
#endif // ENABLE_DEBUG_PRINT
        return __LINE__;
    }

    return 0;
}

static i32 crypto_sha1_test_tc3(void) {
    const u8 string_buf[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const u8 expect_buf[] = {0x84, 0x98, 0x3e, 0x44, //
                             0x1c, 0x3b, 0xd2, 0x6e, //
                             0xba, 0xae, 0x4a, 0xa1, //
                             0xf9, 0x51, 0x29, 0xe5, //
                             0xe5, 0x46, 0x70, 0xf1};

    u8 hash_buf[20] = {0};

    crypto_sha1_Ret ret =
        crypto_sha1_compute(string_buf, (u32)(sizeof(string_buf) - 1), hash_buf, sizeof(hash_buf));

    if (ret != crypto_sha1_Ret_Ok) {
        return __LINE__;
    }

    i32 cmp = crypto_sha1_memcmp(expect_buf, hash_buf, sizeof(expect_buf));
    if (cmp != 0) {
#if defined(ENABLE_DEBUG_PRINT) && (ENABLE_DEBUG_PRINT > 0)
        for (u32 i = 0; i < sizeof(hash_buf); i++) {
            printf("hash[%d] = 0x%02x\n", i, hash_buf[i]);
        }
#endif // ENABLE_DEBUG_PRINT
        return __LINE__;
    }

    return 0;
}

static i32 crypto_sha1_test_tc4(void) {
    const u8 string_buf[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmn"
                            "opjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const u8 expect_buf[] = {0xa4, 0x9b, 0x24, 0x46, //
                             0xa0, 0x2c, 0x64, 0x5b, //
                             0xf4, 0x19, 0xf9, 0x95, //
                             0xb6, 0x70, 0x91, 0x25, //
                             0x3a, 0x04, 0xa2, 0x59};

    u8 hash_buf[20] = {0};

    crypto_sha1_Ret ret =
        crypto_sha1_compute(string_buf, (u32)(sizeof(string_buf) - 1), hash_buf, sizeof(hash_buf));

    if (ret != crypto_sha1_Ret_Ok) {
        return __LINE__;
    }

    i32 cmp = crypto_sha1_memcmp(expect_buf, hash_buf, sizeof(expect_buf));
    if (cmp != 0) {
#if defined(ENABLE_DEBUG_PRINT) && (ENABLE_DEBUG_PRINT > 0)
        for (u32 i = 0; i < sizeof(hash_buf); i++) {
            printf("hash[%d] = 0x%02x\n", i, hash_buf[i]);
        }
#endif // ENABLE_DEBUG_PRINT
        return __LINE__;
    }

    return 0;
}

i32 crypto_sha1_test(void) {
    i32 result;

    result = crypto_sha1_test_tc1();
    if (result != 0) {
        return result;
    }
    result = crypto_sha1_test_tc2();
    if (result != 0) {
        return result;
    }
    result = crypto_sha1_test_tc3();
    if (result != 0) {
        return result;
    }
    result = crypto_sha1_test_tc4();
    if (result != 0) {
        return result;
    }

    return 0;
}

//==================================================================================================
// PRIVATE FUNCTION DEFINITION
//==================================================================================================
