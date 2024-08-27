## Generate EVM private key with pretty address

### How to use

Firstly, install secp256k1 and sodium.

**main.c**
```c
#include "gen
#include <stdio.h>
#include "genethaddr/genethaddr.h"

void print_hex(const uint8_t *data, uint8_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", data[i]);
    printf("\n");
}

uint8_t check_address(const uint8_t *address) {
    // Return true if address satisfies or 0 if not.
    if (
        address[0] == 0 &&
        address[1] == 0
    )
        return 1;

    return 0;
}

int main() {
    size_t nthreads = 8;
    GeneratedEthKey key = generate_private_key(check_address, nthreads);

    print_hex(key.key, 32);
    print_hex(key.address, 20);

    return 0;
}
```

Compile:
```shell
clang \
  -I/opt/homebrew/include \
  -L/opt/homebrew/lib \
  -lsecp256k1 \
  -lsodium \
  -o main \
  main.c genethaddr/keccak256.c genethaddr/genethaddr.c
```
