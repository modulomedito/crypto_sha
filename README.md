# crypto_sha

SHA (Secure Hash Algorithm) cryptography algorithm.
Supports SHA1, SHA256.
Comply to MISRA-C:2012, 2023 rules.

## How To Use?

### 1. Copy all files in the `src` folder to your project, which are:

- crypto_sha1.c
- crypto_sha1.h
- crypto_sha256.c
- crypto_sha256.h
- rustlike_types.h

### 2. In your cryptography source code:

#### If you want to execute the SHA256 algorithm synchronously

```c
// File: main.c

#include "crypto_sha256.h"
#include <string.h>

u8 main_data_buf[] = {"abc"};
u8 main_hash_buf[CRYPTO_SHA256_BLOCK_U8_SIZE];

i32 main(void) {
    crypto_sha256_compute(
        main_data_buf,                         // Input, data buffer
        strlen((const ichar*)main_data_buf),   // Input, data buffer size in bytes
        main_hash_buf,                         // Output, the hash (32 bytes)
        sizeof(main_hash_buf)
    );
}
```

#### If you want to execute the SHA256 algorithm asynchronously

```c
// File: myfile.c

#include "crypto_sha256.h"
#include <string.h>

crypto_sha256_Handle myfile_sha_handle;

// Data to hash
const u8 myfile_data_buf[] = {
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
};

// Index for looping through the data
u32 myfile_index = 0;

// Buffer for saving the SHA256 hash result
u8 myfile_hash_buf[CRYPTO_SHA256_BLOCK_U8_SIZE];

// Your init function
void myfile_init(void) {
    crypto_sha256_Handle_init(&myfile_sha_handle);
}

// Your preriodical task function, called multiple times
void myfile_task(void) {
    u32 data_size = strlen((const ichar*)myfile_data_buf);
    if (myfile_index <= data_size) {
        crypto_sha256_Handle_update(
            &myfile_sha_handle,
            &myfile_data_buf[myfile_index],
            8
        );
        myfile_index += 8;
    }
}

// Your finalize function, where you want to use the hash result
void myfile_final(void) {
    crypto_sha256_Handle_finalize(&myfile_sha_handle, myfile_hash_buf, sizeof(myfile_hash_buf));

    // Compare the result with your expected value:
    u8 expected_hash_buf[CRYPTO_SHA256_BLOCK_U8_SIZE] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    i32 ret = memcmp(expected_hash_buf, myfile_hash_buf,
                     CRYPTO_SHA256_BLOCK_U8_SIZE * sizeof(u8));
    if (ret != 0) {
        // Compare failed handling
    }
}
```

## How To Test?

Test with xmake, you need to install [xmake](https://xmake.io/) first.

```bash
git clone https://github.com/modulomedito/crypto_sha.git
cd crypto_sha
xmake test -v
```
