# secp256k1-export

The Bitcoin [secp256k1](https://github.com/bitcoin-core/secp256k1/) library, based on version 0.6.0, modified to export scalar and point manipulation functions.

## Usage
1. Build the library

```bash
./autogen.sh
./configure
make
```

2. Link `.libs/libsecp256k1.a` or `.libs/libsecp256k1.{so,dylib}` to your project
3. Include `include/secp256k1_export.h` and call functions defined in the header

## Sample code
```c
#include <stdio.h>
#include "secp256k1_export.h"

int main() {
  secp256k1_gej_alias g;
  secp256k1_gej_alias sum1;
  secp256k1_gej_alias sum2;
  secp256k1_gej_alias prod;
  secp256k1_scalar four;

  secp256k1_export_group_get_base_point(&g);
  secp256k1_export_group_add(&sum1, &g, &g);
  secp256k1_export_group_add(&sum2, &sum1, &sum1);

  secp256k1_export_scalar_set_int(&four, 4);
  secp256k1_export_group_ecmult(&prod, &four);

  int r = secp256k1_export_group_eq(&sum2, &prod);
  printf("%s\n", r == 1 ? "equal" : "not equal");

  return 0;
}
```
