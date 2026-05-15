# crypto_sha

SHA (Secure Hash Algorithm) cryptography algorithm.
Supports SHA256.

## How To Use?

### 1. Copy all files in the `src` folder to your project, which are:

- crypto_sha256.c
- crypto_sha256.h
- rustlike_types.h

### 2. In your cryptography source code:

#### If you want to execute the SHA256 algorithm synchronously

```c
// File: main.c

#include "crypto_sha256.h"
#include <string.h>

u8 main__data_buf[] = {"abc"};
u8 main__hash_buf[CRYPTO_SHA256__BLOCK_U8_SIZE];

i32 main(void) {
    crypto_sha256__compute(
        main__data_buf,                         // Input, data buffer
        strlen((const ichar*)main__data_buf),   // Input, data buffer size in bytes
        main__hash_buf                          // Output, the hash (32 bytes)
    );
}
```

#### If you want to execute the SHA256 algorithm asynchronously

```c
// File: myfile.c

#include "crypto_sha256.h"
#include <string.h>

crypto_sha256__Handle myfile__sha_handle;

// Data to hash
const u8 myfile__data_buf[] = {
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
};

// Index for looping through the data
u32 myfile__index = 0;

// Buffer for saving the SHA256 hash result
u8 myfile__hash_buf[CRYPTO_SHA256__BLOCK_U8_SIZE];

// Your init function
void myfile__init(void) {
    crypto_sha256__Handle_init(&myfile__sha_handle);
}

// Your preriodical task function, called multiple times
void myfile__task(void) {
    u32 data_size = strlen((const ichar*)myfile__data_buf);
    if (myfile__index <= data_size) {
        crypto_sha256__Handle_update(
            &myfile__sha_handle,
            &myfile__data_buf[myfile__index],
            8
        );
        myfile__index += 8;
    }
}

// Your finalize function, where you want to use the hash result
void myfile__final(void) {
    crypto_sha256__Handle_finalize(&myfile__sha_handle, myfile__hash_buf);

    // Compare the result with your expected value:
    u8 expected_hash_buf[CRYPTO_SHA256__BLOCK_U8_SIZE] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    i32 ret = memcmp(expected_hash_buf, myfile__hash_buf,
                     CRYPTO_SHA256__BLOCK_U8_SIZE * sizeof(u8));
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
